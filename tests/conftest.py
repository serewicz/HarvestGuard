import os
import sys

# Ensure the repo root (containing scanner/, analyzer/, dashboard/) is importable
# regardless of how pytest is invoked.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
