import sqlite3
import datetime

conn = sqlite3.connect('mock_forensic_data.sqlite')
c = conn.cursor()

# 1. Create a fake Contacts table
c.execute('''CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, phone TEXT)''')
c.execute("INSERT INTO contacts (name, phone) VALUES ('Vikram Boss', '+919876543210')")

# 2. Create a fake SMS table (Bank alerts)
c.execute('''CREATE TABLE sms (id INTEGER PRIMARY KEY, address TEXT, body TEXT, date INTEGER)''')
now_ms = int(datetime.datetime.now().timestamp() * 1000)
c.execute(f"INSERT INTO sms (address, body, date) VALUES ('AD-SBIINB-S', 'Rs.50,000 debited from A/c XX4821. UTR 630914829104', {now_ms})")

# 3. Create a fake WhatsApp messages table
c.execute('''CREATE TABLE messages (id INTEGER PRIMARY KEY, key_remote_jid TEXT, data TEXT, timestamp INTEGER)''')
c.execute(f"INSERT INTO messages (key_remote_jid, data, timestamp) VALUES ('919876543210@s.whatsapp.net', 'Send the USDT to my TronLink address TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf', {now_ms})")

# 4. Create a fake PhonePe transactions table
c.execute('''CREATE TABLE phonepe_transactions (id INTEGER PRIMARY KEY, amount_paise INTEGER, utr TEXT, status TEXT)''')
c.execute("INSERT INTO phonepe_transactions (amount_paise, utr, status) VALUES (5000000, '630914829104', 'SUCCESS')")

conn.commit()
conn.close()

print("✅ Created mock_forensic_data.sqlite successfully!")