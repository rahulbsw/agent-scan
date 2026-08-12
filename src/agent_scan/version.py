from importlib.metadata import PackageNotFoundError, version

try:
    version_info = version("open-agent-scan")
except PackageNotFoundError:
    try:
        version_info = version("agent-scan")
    except PackageNotFoundError:
        version_info = "unknown"
