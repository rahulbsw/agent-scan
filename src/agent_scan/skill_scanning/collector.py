from __future__ import annotations

import hashlib
import os
import stat
import time
from typing import TYPE_CHECKING

from agent_scan.skill_scanning.models import Artifact, Limitation, Limits, Report

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


class BudgetExceeded(Exception):
    pass


def collect(
    target: Path,
    report: Report,
    limits: Limits,
    inspect_text: Callable[[str, str, str, Callable[[], None]], None],
    *,
    exclude: Path | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    """Read via anchored no-follow descriptors; never follow links from a bundle.

    Platforms without these filesystem primitives fail closed. The deadline is
    cooperative, not a hard timeout for a stalled filesystem operation.
    """
    coverage = report.coverage
    started = clock()

    def note(path: str, reason: str) -> None:
        coverage.status = "partial"
        coverage.limitations.append(Limitation(path=path, reason=reason))

    def check_time() -> None:
        if clock() - started >= limits.max_seconds:
            raise BudgetExceeded("time_limit")

    def read_file(parent: int, name: str, relative: str) -> None:
        check_time()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                note(relative, "not_regular_file")
                return
            remaining = limits.max_total_bytes - coverage.bytes_read
            if remaining <= 0:
                raise BudgetExceeded("total_bytes_limit")
            # The extra probe byte is charged too; no reliance on a racy st_size.
            allowance = min(limits.max_file_bytes + 1, remaining)
            chunks: list[bytes] = []
            count = 0
            while count < allowance:
                check_time()
                chunk = os.read(fd, min(65_536, allowance - count))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
                coverage.bytes_read += len(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        coverage.files_read += 1
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            note(relative, "file_changed_during_read")
            return
        if count > limits.max_file_bytes:
            note(relative, "file_bytes_limit")
            return
        if count == allowance and (after.st_size > count or allowance < limits.max_file_bytes + 1):
            note(relative, "total_bytes_limit")
            return
        data = b"".join(chunks)
        digest = hashlib.sha256(data).hexdigest()
        try:
            text = data.decode("utf-8")
            if "\x00" in text:
                raise UnicodeError
        except UnicodeError:
            report.artifacts.append(Artifact(path=relative, sha256=digest, size_bytes=count, analysis="unsupported"))
            note(relative, "unsupported_content")
            return
        report.artifacts.append(Artifact(path=relative, sha256=digest, size_bytes=count, analysis="text"))
        inspect_text(relative, text, digest, check_time)
        check_time()

    def walk(directory: int, prefix: str, depth: int) -> None:
        if depth > limits.max_depth:
            note(prefix, "depth_limit")
            return
        entries = []
        with os.scandir(directory) as iterator:
            for entry in iterator:
                check_time()
                if coverage.entries_seen >= limits.max_entries:
                    raise BudgetExceeded("entry_limit")
                coverage.entries_seen += 1
                entries.append(entry)
        for entry in sorted(entries, key=lambda item: item.name):
            check_time()
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                relative.encode("utf-8")
            except UnicodeEncodeError:
                note(relative.encode("utf-8", errors="backslashreplace").decode("utf-8"), "unsupported_filename")
                continue
            try:
                info = entry.stat(follow_symlinks=False)
                if exclude is not None and (target / relative).absolute() == exclude:
                    note(relative, "caller_selected_baseline")
                elif stat.S_ISLNK(info.st_mode):
                    note(relative, "symlink_rejected")
                elif stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, directory_flags, dir_fd=directory)
                    try:
                        walk(child, relative, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    read_file(directory, entry.name, relative)
                else:
                    note(relative, "not_regular_file")
            except OSError:
                note(relative, "unreadable_or_replaced")

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not (
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
        and os.scandir in os.supports_fd
    ):
        coverage.status = "failed"
        report.execution_successful = False
        coverage.limitations.append(Limitation(path=".", reason="secure_filesystem_operations_unavailable"))
        return
    try:
        target = target.expanduser().absolute()
        info = target.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlink_target_rejected")
        if stat.S_ISDIR(info.st_mode):
            fd = os.open(target, directory_flags)
            try:
                walk(fd, "", 0)
            finally:
                os.close(fd)
        elif stat.S_ISREG(info.st_mode):
            coverage.entries_seen += 1
            try:
                target.name.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError("unsupported_filename") from error
            if exclude is not None and target == exclude:
                note(target.name, "caller_selected_baseline")
                return
            parent = os.open(target.parent, directory_flags)
            try:
                read_file(parent, target.name, target.name)
            finally:
                os.close(parent)
        else:
            raise ValueError("not_regular_target")
    except BudgetExceeded as error:
        note(".", str(error))
    except (OSError, ValueError):
        coverage.status = "failed"
        report.execution_successful = False
        coverage.limitations.append(Limitation(path=".", reason="unreadable_or_unsafe_target"))
