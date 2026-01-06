#!/usr/bin/env python3
import sys
import os
import pefile
import struct

def read_ascii_art(art_file):
    with open(art_file, 'r', encoding='utf-8') as f:
        return [line.rstrip() for line in f.readlines()]

def create_art_data(ascii_lines):
    data = b""
    base_addr = 0x140061000

    for i, line in enumerate(ascii_lines):
        addr = base_addr + (i * 16)
        clean_line = ''.join(c if 32 <= ord(c) < 127 else ' ' for c in line)
        formatted = f"_femboy:{addr:016X}  text \"UTF-8\", '{clean_line}',0Ah\n"
        data += formatted.encode('ascii', errors='replace')

    return data

def align(value, alignment):
    return ((value + alignment - 1) // alignment) * alignment

def inject_ascii_art(pe_path, output_path, ascii_lines):
    print(f"[*] Loading PE: {pe_path}")
    pe = pefile.PE(pe_path)

    art_data = create_art_data(ascii_lines)
    print(f"[+] Created art data: {len(art_data)} bytes ({len(ascii_lines)} lines)")

    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment

    last_section = pe.sections[-1]
    new_section_rva = align(
        last_section.VirtualAddress + last_section.Misc_VirtualSize,
        section_alignment
    )
    new_section_raw_offset = align(
        last_section.PointerToRawData + last_section.SizeOfRawData,
        file_alignment
    )

    virtual_size = len(art_data)
    raw_size = align(len(art_data), file_alignment)

    print(f"[*] New section at RVA: 0x{new_section_rva:X}, File offset: 0x{new_section_raw_offset:X}")

    padded_data = art_data + (b'\x00' * (raw_size - len(art_data)))

    # modify the actual debug directory
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
            if debug_entry.struct.Type == 2:
                debug_offset = debug_entry.struct.PointerToRawData
                original_size = debug_entry.struct.SizeOfData

                debug_data = pe.__data__[debug_offset:debug_offset + original_size]

                if debug_data[0:4] == b'RSDS':
                    guid_data = debug_data[4:20]
                    age_data = debug_data[20:24]
                    pdb_path_bytes = debug_data[24:]

                    null_pos = pdb_path_bytes.find(b'\x00')
                    if null_pos != -1:
                        pdb_path_bytes = pdb_path_bytes[:null_pos]

                    original_path = pdb_path_bytes.decode('utf-8', errors='ignore')
                    print(f"[*] Original PDB: {original_path}")

                    new_lines = ["", ""]
                    new_lines.extend(ascii_lines[:15])
                    new_lines.append("")

                    new_path = '\n'.join(new_lines) + '\x00'
                    new_path_bytes = new_path.encode('utf-8', errors='replace')
                    new_debug_data = b'RSDS' + guid_data + age_data + new_path_bytes

                    section_data = new_debug_data + b'\n\n' + b'='*60 + b'\n' + art_data
                    padded_data = section_data + (b'\x00' * (raw_size - len(section_data)))

                    debug_entry.struct.AddressOfRawData = new_section_rva
                    debug_entry.struct.PointerToRawData = new_section_raw_offset
                    debug_entry.struct.SizeOfData = len(new_debug_data)

                    print(f"[+] Modified PDB path")
                    break

    # get the original PE data WITHOUT any modifications
    pe_data = bytearray(pe.write())

    print(f"[DEBUG] Original PE size: {len(pe_data)} bytes")
    print(f"[DEBUG] Original section count: {len(pe.sections)}")

    # calculate offsetsz
    e_lfanew = pe.DOS_HEADER.e_lfanew
    section_count_offset = e_lfanew + 4 + 2  # After PE signature + Machine field
    section_table_offset = e_lfanew + 4 + pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader
    size_of_image_offset = e_lfanew + 4 + 20 + 56  # In OPTIONAL_HEADER

    original_section_count = len(pe.sections)
    new_section_header_offset = section_table_offset + (40 * original_section_count)

    print(f"[DEBUG] Section table at: 0x{section_table_offset:X}")
    print(f"[DEBUG] New section header will be at: 0x{new_section_header_offset:X}")

    # check what's currently at that offset
    if new_section_header_offset < len(pe_data):
        current_data = pe_data[new_section_header_offset:new_section_header_offset+40]
        print(f"[DEBUG] Current data at offset: {current_data[:8].hex()}")

    # build new section header
    section_header = struct.pack(
        '<8sIIIIIIHHI',
        b'.femboy\x00',
        virtual_size,
        new_section_rva,
        raw_size,
        new_section_raw_offset,
        0,  # PointerToRelocations
        0,  # PointerToLinenumbers
        0,  # NumberOfRelocations
        0,  # NumberOfLinenumbers
        0x40000040  # Characteristics
    )

    # extend pe_data if needed to fit section header
    if new_section_header_offset + 40 > len(pe_data):
        gap = new_section_header_offset - len(pe_data)
        print(f"[DEBUG] Extending by {gap} bytes for section header")
        pe_data.extend(b'\x00' * gap)
        pe_data.extend(b'\x00' * 40)

    # write the neww section header
    pe_data[new_section_header_offset:new_section_header_offset + 40] = section_header
    print(f"[DEBUG] Wrote section header at 0x{new_section_header_offset:X}")

    # update
    new_count = original_section_count + 1
    pe_data[section_count_offset:section_count_offset+2] = struct.pack('<H', new_count)
    print(f"[DEBUG] Updated section count to {new_count}")

    # 2nd update
    new_size_of_image = align(new_section_rva + virtual_size, section_alignment)
    pe_data[size_of_image_offset:size_of_image_offset+4] = struct.pack('<I', new_size_of_image)
    print(f"[DEBUG] Updated SizeOfImage to 0x{new_size_of_image:X}")

    # extend to data offset
    if len(pe_data) < new_section_raw_offset:
        gap = new_section_raw_offset - len(pe_data)
        print(f"[DEBUG] Padding {gap} bytes before section data")
        pe_data.extend(b'\x00' * gap)

    # append new section data
    pe_data.extend(padded_data)

    # write output to file
    with open(output_path, 'wb') as f:
        f.write(pe_data)

    # ezz
    print(f"[+] Done! Saved to: {output_path}")
    print(f"[+] Final size: {len(pe_data):,} bytes")

    pe.close()

def main():
    if len(sys.argv) != 4:
        print("memefactory")
        print("=" * 60)
        print("\nUsage: python memefactory.py <input.exe> <output.exe> <ascii_art.txt>")
        print("\nExample:")
        print("  python memefactory.py original.sys new.sys amongus.txt")
        print("\nRequirements:")
        print("  pip install pefile")
        sys.exit(1)

    input_pe = sys.argv[1]
    output_pe = sys.argv[2]
    ascii_art = sys.argv[3]

    if not os.path.exists(input_pe):
        print(f"[-] Error: input file not found: {input_pe}")
        sys.exit(1)

    if not os.path.exists(ascii_art):
        print(f"[-] Error: ascii art not found: {ascii_art}")
        sys.exit(1)

    try:
        import pefile
    except ImportError:
        print("[-] Error: pefile not installed u nupid stigger")
        print("[*] Run: pip install pefile")
        sys.exit(1)

    print("[*] memefactory")
    print("=" * 60)

    art_lines = read_ascii_art(ascii_art)
    print(f"[+] Loaded {len(art_lines)} lines of ASCII art\n")

    try:
        inject_ascii_art(input_pe, output_pe, art_lines)
        print("\n[+] WOOHOO! All done!")
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
