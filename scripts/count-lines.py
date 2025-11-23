#!/usr/bin/env python3
"""
Script to count lines of code in the Track Record Enclave project
"""

import os
from pathlib import Path
from collections import defaultdict

EXCLUDE_DIRS = {
    'node_modules', 'dist', 'build', 'coverage', '.git',
    '.next', 'out', '__pycache__', '.pytest_cache', 'venv'
}

EXCLUDE_FILES = {
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'
}

def should_exclude(path):
    """Check if a path should be excluded"""
    parts = Path(path).parts
    for part in parts:
        if part in EXCLUDE_DIRS:
            return True
    if Path(path).name in EXCLUDE_FILES:
        return True
    return False

def count_lines_in_file(filepath):
    """Count lines in a single file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return len(f.readlines())
    except:
        return 0

def get_file_extension(filepath):
    """Get the file extension"""
    ext = Path(filepath).suffix
    if not ext and 'Dockerfile' in Path(filepath).name:
        return '.dockerfile'
    if not ext and 'docker-compose' in Path(filepath).name:
        return '.docker-compose'
    return ext

def main():
    print("=" * 50)
    print("  Lines of Code Counter")
    print("=" * 50)
    print()

    root_dir = Path(__file__).parent.parent

    stats = defaultdict(lambda: {'lines': 0, 'files': 0})
    total_lines = 0
    total_files = 0

    for root, dirs, files in os.walk(root_dir):
        # Remove excluded directories from dirs to prevent walking into them
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for file in files:
            filepath = Path(root) / file

            if should_exclude(filepath):
                continue

            lines = count_lines_in_file(filepath)
            if lines == 0:
                continue

            ext = get_file_extension(filepath)
            stats[ext]['lines'] += lines
            stats[ext]['files'] += 1
            total_lines += lines
            total_files += 1

    sorted_stats = sorted(stats.items(), key=lambda x: x[1]['lines'], reverse=True)

    print(f"📊 Total: {total_lines:,} lines in {total_files} files")
    print()
    print("📁 Lines by File Type:")
    print()

    ext_names = {
        '.ts': 'TypeScript',
        '.js': 'JavaScript',
        '.json': 'JSON',
        '.md': 'Markdown',
        '.sh': 'Shell Script',
        '.py': 'Python',
        '.yml': 'YAML',
        '.yaml': 'YAML',
        '.dockerfile': 'Dockerfile',
        '.docker-compose': 'Docker Compose',
        '.env': 'Environment',
        '.sql': 'SQL',
        '.prisma': 'Prisma Schema',
        '.txt': 'Text',
        '.gitignore': 'Git Ignore',
        '.dockerignore': 'Docker Ignore',
    }

    for ext, data in sorted_stats:
        ext_name = ext_names.get(ext, ext if ext else 'No extension')
        print(f"  {ext_name:20} {data['lines']:>8,} lines in {data['files']:>4} files")

    print()
    print("=" * 50)
    print("✅ Analysis complete!")
    print("=" * 50)

if __name__ == '__main__':
    main()
