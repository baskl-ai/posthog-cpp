#!/usr/bin/env python3
"""
Update version in all project files from CHANGELOG.md

This script reads the latest version from CHANGELOG.md and updates:
- CMakeLists.txt (project VERSION)
- include/posthog/posthog.h (POSTHOG_VERSION_* defines)

Usage:
    python3 scripts/update_version.py
"""

import re
import sys
from pathlib import Path


def extract_version_from_changelog():
    """Extract the latest version from CHANGELOG.md"""
    changelog_path = Path(__file__).parent.parent / 'CHANGELOG.md'

    if not changelog_path.exists():
        print("Error: CHANGELOG.md not found")
        sys.exit(1)

    content = changelog_path.read_text()

    # Find first version section: ## [X.Y.Z]
    match = re.search(r'##\s+\[(\d+\.\d+\.\d+)\]', content)

    if not match:
        print("Error: No version found in CHANGELOG.md")
        print("Expected format: ## [X.Y.Z] - YYYY-MM-DD")
        sys.exit(1)

    return match.group(1)


def update_cmake(version):
    """Update version in CMakeLists.txt"""
    cmake_file = Path(__file__).parent.parent / 'CMakeLists.txt'

    if not cmake_file.exists():
        print("Warning: CMakeLists.txt not found, skipping")
        return False

    content = cmake_file.read_text()

    # Replace project(posthog-cpp VERSION X.Y.Z ...)
    new_content = re.sub(
        r'(project\(posthog-cpp\s+VERSION\s+)[\d.]+',
        rf'\g<1>{version}',
        content
    )

    if content != new_content:
        cmake_file.write_text(new_content)
        return True
    return False


def update_header(version):
    """Update version defines in posthog.h"""
    header_file = Path(__file__).parent.parent / 'include/posthog/posthog.h'

    if not header_file.exists():
        print("Warning: include/posthog/posthog.h not found, skipping")
        return False

    content = header_file.read_text()
    major, minor, patch = version.split('.')
    old_content = content

    # Update or add version defines after #define POSTHOG_H
    version_defines = f'''#define POSTHOG_VERSION_MAJOR {major}
#define POSTHOG_VERSION_MINOR {minor}
#define POSTHOG_VERSION_PATCH {patch}
#define POSTHOG_VERSION "{version}"'''

    # Check if version defines already exist
    if '#define POSTHOG_VERSION_MAJOR' in content:
        # Update existing defines
        content = re.sub(
            r'#define POSTHOG_VERSION_MAJOR \d+\n#define POSTHOG_VERSION_MINOR \d+\n#define POSTHOG_VERSION_PATCH \d+\n#define POSTHOG_VERSION "[^"]+"',
            version_defines,
            content
        )
    else:
        # Add after #define POSTHOG_H
        content = content.replace(
            '#define POSTHOG_H\n',
            f'#define POSTHOG_H\n\n{version_defines}\n'
        )

    if content != old_content:
        header_file.write_text(content)
        return True
    return False


def main():
    print("Updating version from CHANGELOG.md...")
    print()

    # Extract version
    version = extract_version_from_changelog()
    major, minor, patch = version.split('.')

    print(f"Found version: {version}")
    print()

    # Update all files
    updated = []

    if update_cmake(version):
        updated.append("CMakeLists.txt")
        print(f"[OK] Updated CMakeLists.txt -> VERSION {version}")

    if update_header(version):
        updated.append("include/posthog/posthog.h")
        print(f"[OK] Updated include/posthog/posthog.h -> POSTHOG_VERSION \"{version}\"")

    print()

    if not updated:
        print("[OK] All files already at version", version)
        return

    print(f"[OK] Successfully updated {len(updated)} file(s) to version {version}")
    print()
    print("Next steps:")
    print("1. Build: cmake -S . -B build && cmake --build build")
    print("2. Test: ./build/examples/basic")
    print(f"3. Commit: git add . && git commit -m 'chore: bump version to {version}'")
    print(f"4. Tag: git tag v{version} && git push origin v{version}")


if __name__ == '__main__':
    main()
