import asyncio
import sys

from agent_scan.cli import MissingIdentifierError, main


def run():
    try:
        asyncio.run(main())
    except MissingIdentifierError:
        sys.exit(1)


if __name__ == "__main__":
    run()
