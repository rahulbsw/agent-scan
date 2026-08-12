import asyncio
import sys
from pathlib import Path

from agent_scan.cli import MissingIdentifierError, main

PRIMARY_COMMAND = "open-agent-scan"
LEGACY_COMMAND = "agent-scan"


def _maybe_warn_legacy_alias(argv0: str | None = None) -> None:
    invoked = Path(argv0 or sys.argv[0]).name.lower()
    if invoked in {LEGACY_COMMAND, f"{LEGACY_COMMAND}.exe"}:
        print(
            "`agent-scan` is a compatibility alias. Use `open-agent-scan`; "
            "the legacy alias will be removed after the migration window.",
            file=sys.stderr,
        )


def run():
    _maybe_warn_legacy_alias()
    try:
        asyncio.run(main())
    except MissingIdentifierError:
        sys.exit(1)


if __name__ == "__main__":
    run()
