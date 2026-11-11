from parsers.enterprise_1tb_chat_and_container_engine import scan_raw_image_sliding_window

print("Scanning 50MB disk image for SQLite databases...")
found_count = 0

for artifact in scan_raw_image_sliding_window('test_evidence/test_disk.dd', chunk_size=16*1024*1024, overlap=64*1024):
    if artifact['type'] == 'sqlite_db':
        found_count += 1
        offset = artifact['physical_offset_hex']
        p_size = artifact['page_size']
        b_size = artifact['byte_size']
        print(f"Found DB! Offset: {offset}, Page Size: {p_size}, Size: {b_size} bytes")

print(f"Total databases found: {found_count}")