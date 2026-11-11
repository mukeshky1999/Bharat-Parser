import os
import sqlite3
import random
import time
import shutil
from datetime import datetime, timedelta

OUTPUT_DIR = "test_evidence"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- Helper Functions ---
def random_phone():
    return f"+91{random.randint(7000000000, 9999999999)}"

def random_vpa():
    names = ["rakesh", "priya", "amit", "neha", "vikram", "sunita", "mule_account"]
    banks = ["okhdfcbank", "okicici", "ybl", "paytm", "upi"]
    return f"{random.choice(names)}{random.randint(10, 99)}@{random.choice(banks)}"

def random_utr():
    return str(random.randint(100000000000, 999999999999))

def random_date():
    return (datetime.now() - timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%d %H:%M:%S")

# --- 1. WhatsApp Database ---
def create_whatsapp_db():
    print("[*] Creating WhatsApp database (msgstore.db)...")
    path = os.path.join(OUTPUT_DIR, "msgstore.db")
    
    # Cleanup old files to prevent locking issues
    for ext in ["", "-wal", "-shm"]:
        if os.path.exists(path + ext):
            os.remove(path + ext)
    
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    
    # Force WAL mode and disable auto-checkpointing so the -wal file stays on disk
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA wal_autocheckpoint=0;")
    
    cursor.execute("""
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_remote_jid TEXT,
            key_from_me INTEGER,
            data TEXT,
            timestamp INTEGER,
            status INTEGER
        )
    """)
    
    # Insert Active Messages
    for i in range(50):
        cursor.execute("INSERT INTO message (key_remote_jid, key_from_me, data, timestamp, status) VALUES (?, ?, ?, ?, ?)",
                       (random_phone(), random.randint(0,1), f"Active message {i} containing a fake UPI {random_vpa()}", int(time.time()*1000), 1))
    
    # Insert Messages that will be DELETED (to test freelist/WAL carving)
    cursor.executemany("INSERT INTO message (key_remote_jid, key_from_me, data, timestamp, status) VALUES (?, ?, ?, ?, ?)",
        [(random_phone(), 1, f"SECRET DELETED MSG {i} - Transfer to {random_vpa()} Amount: Rs. 5000", int(time.time()*1000), 1) for i in range(20)])
    
    conn.commit()
    
    # Delete the secret messages (moves them to freelist/WAL)
    cursor.execute("DELETE FROM message WHERE data LIKE 'SECRET DELETED MSG%'")
    conn.commit()
    
    # Preserve -wal and -shm before closing connection so they remain on disk for forensics
    wal_file = path + "-wal"
    shm_file = path + "-shm"
    wal_backup = path + "-wal.bak"
    shm_backup = path + "-shm.bak"
    if os.path.exists(wal_file):
        shutil.copyfile(wal_file, wal_backup)
    if os.path.exists(shm_file):
        shutil.copyfile(shm_file, shm_backup)

    # Close connection (SQLite would normally auto-checkpoint on last close)
    conn.close()

    # Restore uncheckpointed WAL & SHM files to simulate a live/dirty uncheckpointed acquisition
    if os.path.exists(wal_backup):
        shutil.move(wal_backup, wal_file)
    if os.path.exists(shm_backup):
        shutil.move(shm_backup, shm_file)
    print(f"    -> Generated {path} (and -wal file)")

# --- 2. Google Pay Database ---
def create_gpay_db():
    print("[*] Creating Google Pay database (paisa.db)...")
    path = os.path.join(OUTPUT_DIR, "paisa.db")
    for ext in ["", "-wal", "-shm"]:
        if os.path.exists(path + ext):
            os.remove(path + ext)
    
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    
    # FIXED: Quoted "Transaction" because it is a reserved SQL keyword
    cursor.execute("""
        CREATE TABLE "Transaction" (
            id TEXT PRIMARY KEY,
            amount REAL,
            sender_vpa TEXT,
            receiver_vpa TEXT,
            utr TEXT,
            timestamp TEXT
        )
    """)
    
    # Insert transactions
    for i in range(30):
        cursor.execute('INSERT INTO "Transaction" (id, amount, sender_vpa, receiver_vpa, utr, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
                       (f"TX{i}", round(random.uniform(10.0, 50000.0), 2), random_vpa(), random_vpa(), random_utr(), random_date()))
    
    conn.commit()
    conn.close()
    print(f"    -> Generated {path}")

# --- 3. Raw Disk Image (Sliding Window Carver Test) ---
def create_raw_disk_image():
    print("[*] Creating Raw Disk Image (test_disk.dd)...")
    path = os.path.join(OUTPUT_DIR, "test_disk.dd")
    
    # Create a 50MB file filled with random noise (simulating unallocated disk space)
    with open(path, "wb") as f:
        f.write(os.urandom(50 * 1024 * 1024))
        
    # Inject the SQLite databases at specific offsets to simulate a fragmented disk
    # Offset 1: 10MB in (0x00A00000)
    # Offset 2: 35MB in (0x02300000)
    
    def inject_file_to_image(img_path, file_to_inject, offset):
        with open(file_to_inject, "rb") as src:
            data = src.read()
        with open(img_path, "r+b") as dst:
            dst.seek(offset)
            dst.write(data)
        print(f"    -> Injected {os.path.basename(file_to_inject)} at offset {hex(offset)}")

    inject_file_to_image(path, os.path.join(OUTPUT_DIR, "msgstore.db"), 10 * 1024 * 1024)
    inject_file_to_image(path, os.path.join(OUTPUT_DIR, "paisa.db"), 35 * 1024 * 1024)
    print(f"    -> Generated {path} (50MB)")

# --- 4. Fake Logical Extraction Directory ---
def create_logical_extraction():
    print("[*] Creating Logical Extraction Folder Structure...")
    base_dir = os.path.join(OUTPUT_DIR, "android_logical_extraction")
    if os.path.exists(base_dir):
        shutil.rmtree(base_dir)
    
    # Create Android-like paths
    paths = {
        "data/data/com.whatsapp/databases/": "msgstore.db",
        "data/data/com.google.android.apps.nbu.paisa.user/databases/": "paisa.db"
    }
    
    for rel_path, db_file in paths.items():
        full_dir = os.path.join(base_dir, rel_path)
        os.makedirs(full_dir, exist_ok=True)
        
        # Copy the generated DBs and WAL/SHM companion files
        src = os.path.join(OUTPUT_DIR, db_file)
        dst = os.path.join(full_dir, db_file)
        shutil.copy2(src, dst)
        for companion_ext in ["-wal", "-shm"]:
            if os.path.exists(src + companion_ext):
                shutil.copy2(src + companion_ext, dst + companion_ext)
        
    # Create a fake media file (should be ignored by materializer to test zero-OOM)
    media_dir = os.path.join(base_dir, "data/media/0/WhatsApp/Media")
    os.makedirs(media_dir, exist_ok=True)
    with open(os.path.join(media_dir, "fake_video.mp4"), "wb") as f:
        f.write(os.urandom(5 * 1024 * 1024)) # 5MB dummy video
        
    print(f"    -> Generated {base_dir}")

if __name__ == "__main__":
    print("=== BHARAT-PA FORENSIC TEST DATA GENERATOR ===")
    create_whatsapp_db()
    create_gpay_db()
    create_logical_extraction()
    create_raw_disk_image()
    print("\n[+] Done! You now have realistic test data in the 'test_evidence' folder.")