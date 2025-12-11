import streamlit as st
import json
import os
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime

# --- CONFIGURATION ---
DB_FILE = 'chat_db.json'
REFRESH_RATE = 2  # Seconds to auto-refresh for new messages

# --- MOCKED BACKEND (File Storage) ---
# This mimics the MongoDB server. It stores encrypted blobs.
def load_db():
    if not os.path.exists(DB_FILE):
        return {"messages": [], "locations": {}}
    try:
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    except:
        return {"messages": [], "locations": {}}

def save_db(data):
    with open(DB_FILE, 'w') as f:
        json.dump(data, f)

# --- CRYPTOGRAPHY ENGINE (Client Side) ---
# This runs locally on the user's "Device" (Session State)
# Add this line BEFORE generating keys
st.session_state['user_name'] = user  # Saves "User A" or "User B" to state
if 'private_key' not in st.session_state:
    priv, pub = generate_keys() 
    # ... rest of the code
# Replace your existing generate_keys() function with this:

def generate_keys():
    """Generates keys OR loads them if they already exist on disk."""
    key_file = f"private_key_{st.session_state.get('user_name', 'default')}.pem"
    
    # 1. Try to load existing key from disk
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        # Generate the public key from the loaded private key
        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, pem_public

    # 2. If no file, generate NEW keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 3. Save the new private key to disk
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(key_file, "wb") as f:
        f.write(pem_private)
        
    return private_key, pem_public

def encrypt_message(message, public_key_pem):
    """Encrypts a message using the recipient's Public Key."""
    # Load recipient's public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    
    # Encrypt
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_message(encrypted_b64, private_key):
    """Decrypts a message using the user's Private Key."""
    try:
        ciphertext = base64.b64decode(encrypted_b64)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')
    except Exception as e:
        return "[Error: Decryption Failed]"

# --- PAGE SETUP ---
st.set_page_config(page_title="Secure Chat Prototype", layout="centered", page_icon="🔒")

st.title("🔒 Secure Private Messenger")
st.caption("End-to-End Encrypted Communication Prototype")

# --- AUTHENTICATION & KEY MANAGEMENT ---
# Simulate Login
user = st.sidebar.radio("Select User Identity", ["User A", "User B"])
partner = "User B" if user == "User A" else "User A"

# Initialize Session State (The "Device" Memory)
if 'private_key' not in st.session_state:
    priv, pub = generate_keys()
    st.session_state['private_key'] = priv
    st.session_state['public_key_pem'] = pub.decode('utf-8')
    
    # Publish Public Key to DB (Simulating API call to register user)
    db = load_db()
    if 'keys' not in db: db['keys'] = {}
    db['keys'][user] = st.session_state['public_key_pem']
    save_db(db)

st.sidebar.success(f"Logged in as **{user}**")
st.sidebar.markdown("---")
st.sidebar.info("🔑 **Security Status:**\nKeys Generated & Stored in Session RAM.")

# --- MAIN APP LOGIC ---

# 1. Location Sharing Module
st.subheader("📍 Live Location")
col1, col2 = st.columns([1, 3])

with col1:
    if st.button("📍 Share My Location"):
        # Mock GPS Coordinates (In real app, use geolocator)
        import random
        lat = 28.7041 + (random.random() * 0.01) # Near Delhi
        lon = 77.1025 + (random.random() * 0.01)
        
        db = load_db()
        db['locations'][user] = {"lat": lat, "lon": lon, "time": datetime.now().strftime("%H:%M:%S")}
        save_db(db)
        st.success("Location sent!")

with col2:
    db = load_db()
    partner_loc = db['locations'].get(partner)
    if partner_loc:
        st.map({'lat': [partner_loc['lat']], 'lon': [partner_loc['lon']]}, zoom=14)
        st.caption(f"Partner's last location at {partner_loc['time']}")
    else:
        st.info("Waiting for partner to share location...")

st.markdown("---")

# 2. Chat Module
st.subheader("💬 Private Chat")

# Input Area
with st.form("chat_form", clear_on_submit=True):
    msg_input = st.text_input("Type a message...")
    submitted = st.form_submit_button("Send Encrypted")
    
    if submitted and msg_input:
        db = load_db()
        
        # Check if partner has a public key
        if 'keys' in db and partner in db['keys']:
            partner_pub_key = db['keys'][partner]
            
            # ENCRYPTION HAPPENS HERE
            encrypted_payload = encrypt_message(msg_input, partner_pub_key)
            
            # Save to DB (Server only sees encrypted_payload)
            msg_obj = {
                "from": user,
                "to": partner,
                "payload": encrypted_payload,
                "timestamp": datetime.now().strftime("%H:%M")
            }
            db['messages'].append(msg_obj)
            save_db(db)
        else:
            st.error(f"Waiting for {partner} to come online (Key Exchange Pending)")

# Message Display Area
chat_container = st.container()
db = load_db()

with chat_container:
    # Filter messages for this conversation
    my_msgs = [m for m in db['messages'] if m['to'] == user or m['from'] == user]
    
    if not my_msgs:
        st.info("No messages yet. Start the conversation!")
    
    for msg in my_msgs:
        is_me = msg['from'] == user
        
        if is_me:
            # My messages: I don't store my own plain text in this simple proto, 
            # so I can't decrypt my own sent messages (since I encrypted them with PARTNER'S key).
            # This is standard Public Key behavior.
            with st.chat_message("user"):
                st.write(f"🔒 *[Encrypted Message Sent]*")
                st.caption(f"{msg['timestamp']} ✓")
        else:
            # Partner messages: I can decrypt these with MY private key
            decrypted_text = decrypt_message(msg['payload'], st.session_state['private_key'])
            with st.chat_message("assistant"):
                st.write(decrypted_text)
                st.caption(f"From {partner} • {msg['timestamp']}")

# --- AUTO REFRESH LOOP ---
# This simulates real-time sockets by refreshing the script
time.sleep(REFRESH_RATE)
st.rerun()
