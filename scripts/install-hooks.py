#!/usr/bin/env python3
"""
Install git hooks (cross-platform)
Copies hooks from scripts/hooks/ to .git/hooks/
"""

import os
import shutil
import stat
from pathlib import Path

def main():
    root = Path(__file__).parent.parent
    git_dir = root / '.git'

    if not git_dir.exists():
        # Not a git repo (e.g. installed as dependency) — skip silently
        return 0

    git_hooks_dir = git_dir / 'hooks'
    src_hooks_dir = Path(__file__).parent / 'hooks'

    if not git_hooks_dir.exists():
        print('Warning: .git/hooks directory not found')
        return 0

    # Copy pre-commit hook
    src = src_hooks_dir / 'pre-commit'
    dest = git_hooks_dir / 'pre-commit'

    if not src.exists():
        print('Warning: pre-commit hook source not found')
        return 0

    shutil.copy2(src, dest)

    # chmod +x on Unix (no-op on Windows, but git respects it)
    try:
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        # Ignore chmod errors on Windows
        pass

    print('[OK] Git hooks installed')
    return 0

if __name__ == '__main__':
    exit(main())
