#!/usr/bin/env python3
"""
Inject compiler-rt builtins into the libwsutil.so and fuzzshark link commands
in the cmake-generated ninja build files.

This is needed on aarch64 where clang emits __muloti4 (128-bit overflow multiply)
from UBSan instrumentation, but the symbol isn't automatically linked into shared libs.
"""
import sys
import os
import glob

def find_builtins():
    pattern = '/usr/lib/llvm-*/lib/clang/*/lib/linux/libclang_rt.builtins-*.a'
    matches = glob.glob(pattern)
    return matches[0] if matches else None

def patch_ninja_file(path, builtins, targets):
    with open(path, 'r') as f:
        content = f.read()

    original = content
    for target in targets:
        # Find lines like: LINK_LIBRARIES = ... that belong to the target's build block
        # Ninja build files have: LINK_LIBRARIES = -lfoo -lbar
        # We append the builtins archive to that variable for matching targets
        marker = f'build {target}'
        if marker not in content:
            continue
        # Find the LINK_LIBRARIES line after this build block
        idx = content.find(marker)
        block_end = content.find('\nbuild ', idx + 1)
        if block_end == -1:
            block_end = len(content)
        block = content[idx:block_end]
        if 'LINK_LIBRARIES' in block and builtins not in block:
            patched_block = block.replace(
                'LINK_LIBRARIES = ',
                f'LINK_LIBRARIES = {builtins} ',
                1
            )
            content = content[:idx] + patched_block + content[block_end:]
            print(f"  Patched LINK_LIBRARIES in {path} for target: {target}")

    if content != original:
        with open(path, 'w') as f:
            f.write(content)
        return True
    return False

def main(build_dir):
    builtins = find_builtins()
    if not builtins:
        print("No compiler-rt builtins found, skipping patch.")
        return

    print(f"Using builtins: {builtins}")

    targets = [
        'run/libwsutil.so.0.0.0',
        'run/libwiretap.so.0.0.0',
        'run/libwireshark.so.0.0.0',
        'run/fuzzshark',
    ]

    # Patch the main build.ninja and any sub-ninja files
    ninja_files = [os.path.join(build_dir, 'build.ninja')]
    ninja_files += glob.glob(os.path.join(build_dir, '**', '*.ninja'), recursive=True)

    patched = 0
    for nf in ninja_files:
        if os.path.exists(nf):
            if patch_ninja_file(nf, builtins, targets):
                patched += 1

    print(f"Patched {patched} ninja file(s).")

if __name__ == '__main__':
    build_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    main(build_dir)
