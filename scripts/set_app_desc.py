#!/usr/bin/env python3
"""Set the project name in an ESP-IDF application image.

NervesHub reads `esp_app_desc_t` to decide what an uploaded image is, and
matches `project_name` against the product it was uploaded to. ESP-IDF derives
that field from the CMake project name, which `esp-idf-sys` hardcodes to
`libespidf` — so a Rust application cannot set it, and every Rust image looks
like a product called `libespidf`.

This rewrites the field after the compiler has produced it.

Run it on the **ELF**, before `esptool.py elf2image`. The image's SHA-256 is
computed during that conversion, so patching the ELF keeps it valid; patching
the `.bin` afterwards would invalidate the digest and the bootloader would
refuse to start the image.

    scripts/set_app_desc.py --project-name SmartKiosk path/to/elf

Only the project name. The version has a supported setting —
`CONFIG_APP_PROJECT_VER_FROM_CONFIG=y` with `CONFIG_APP_PROJECT_VER` in
sdkconfig — and rewriting a field that the build system is willing to set for
you is a worse habit than it looks: it moves the value out of the build
configuration, where it can be reviewed, into a step someone can forget.
"""

import argparse
import shutil
import sys

# esp_app_desc_t, from esp_app_format.h. Offsets within the 256 byte struct.
MAGIC = 0xABCD5432
VERSION_OFFSET = 16
PROJECT_NAME_OFFSET = 48
IDF_VER_OFFSET = 112
FIELD_SIZE = 32


def find_descriptor(data: bytes) -> int:
    """The one offset where esp_app_desc_t lives, or exit with a reason.

    The magic alone is four bytes and could occur in compiled code by accident,
    so a single unambiguous hit is required rather than taking the first.
    """
    needle = MAGIC.to_bytes(4, "little")
    hits = []
    start = 0
    while True:
        found = data.find(needle, start)
        if found < 0:
            break
        hits.append(found)
        start = found + 1

    if not hits:
        sys.exit("no esp_app_desc_t found: is this an ESP-IDF application ELF?")
    if len(hits) > 1:
        sys.exit(
            f"found {len(hits)} candidate descriptors at "
            f"{[hex(h) for h in hits]} — refusing to guess"
        )

    return hits[0]


def read_field(data: bytes, base: int, offset: int) -> str:
    raw = data[base + offset : base + offset + FIELD_SIZE]
    end = raw.find(b"\0")
    return (raw if end < 0 else raw[:end]).decode("utf-8", "replace")


def write_field(data: bytearray, base: int, offset: int, value: str) -> None:
    encoded = value.encode("utf-8")
    if len(encoded) >= FIELD_SIZE:
        sys.exit(f"{value!r} is {len(encoded)} bytes; the field holds {FIELD_SIZE - 1} plus a NUL")

    # NUL-pad the whole field: leaving the old tail behind would be read as
    # trailing rubbish by anything scanning to the terminator.
    data[base + offset : base + offset + FIELD_SIZE] = encoded.ljust(FIELD_SIZE, b"\0")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("elf", help="the application ELF, before elf2image")
    parser.add_argument("--project-name", help="what NervesHub matches against the product name")
    parser.add_argument("-o", "--output", help="write here instead of patching in place")
    parser.add_argument("--dry-run", action="store_true", help="report what is there and stop")
    args = parser.parse_args()

    with open(args.elf, "rb") as handle:
        data = bytearray(handle.read())

    base = find_descriptor(bytes(data))

    print(f"esp_app_desc_t at {hex(base)}")
    print(f"  project_name  {read_field(data, base, PROJECT_NAME_OFFSET)!r}")
    print(f"  version       {read_field(data, base, VERSION_OFFSET)!r}")
    print(f"  idf_ver       {read_field(data, base, IDF_VER_OFFSET)!r}")

    if args.dry_run:
        return

    if not args.project_name:
        sys.exit("nothing to do: pass --project-name")

    write_field(data, base, PROJECT_NAME_OFFSET, args.project_name)

    destination = args.output or args.elf
    if args.output:
        shutil.copystat(args.elf, args.elf)

    with open(destination, "wb") as handle:
        handle.write(data)

    print(f"\nwrote {destination}")
    print(f"  project_name  {read_field(data, base, PROJECT_NAME_OFFSET)!r}")


if __name__ == "__main__":
    main()
