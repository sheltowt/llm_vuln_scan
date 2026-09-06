import sys
from pathlib import Path

# Make the fixture app importable as `vulnerable_app` in every test.
sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
