'''Utilities for operating on filesystem.'''

from pathlib import Path

project_root = Path(__file__).resolve().parents[1]
project_name = Path(project_root).name.lower()

build_dir = project_root / 'build'
