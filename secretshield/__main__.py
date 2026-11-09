"""Main entrypoint for `python3 -m secretshield`."""

import sys
from secretshield.cli import main

if __name__ == "__main__":
    sys.exit(main())
