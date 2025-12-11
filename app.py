import streamlit as st
import json
import os
import time
import base64
import random
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# --- CONFIGURATION ---
DB_FILE = 'chat_db.json'
REFRESH_RATE = 2  # Seconds to auto-refresh for new messages

# --- MOCKED BACKEND (File Storage) ---
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

# --- CRYPTOGRAPHY ENGINE ---

def generate_keys():
    """Generates keys OR loads them if they already exist on disk (Persistence Fix)."""
    current_user = st.session_state.get('user_name', 'unknown')
    key_file = f"private_key_{current_user}.pem"
    
    # 1. Try to load existing key from disk
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
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
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
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
st.set_page_config(page_title="Secure Chat", layout="centered", page_icon="🔒")
st.title("🔒 Secure Private Messenger")

# --- AUTHENTICATION & KEY MANAGEMENT ---

# 1. ASK USER IDENTITY FIRST (Correct Order)
user = st.sidebar.radio("Select User Identity", ["User A", "User B"])
partner = "User B" if user == "User A" else "User A"

# 2. SAVE TO SESSION STATE
st.session_state['user_name'] = user 
st.sidebar.success(f"Logged in as **{user}**")

# 3. INITIALIZE KEYS (Persistent)
if 'private_key' not in st.session_state:
    priv, pub = generate_keys()
    st.session_state['private_key'] = priv
    st.session_state['public_key_pem'] = pub.decode('utf-8')
    
    # Publish Public Key to DB
    db = load_db()
    if 'keys' not in db: db['keys'] = {}
    db['keys'][user] = st.session_state['public_key_pem']
    save_db(db)

st.sidebar.markdown("---")
st.sidebar.info("🔑 **Status:** Encryption Keys Active")

# --- MAIN APP LOGIC ---

# 1. Location Sharing Module (Google Maps Edition)
st.subheader("📍 Live Location")
col1, col2 = st.columns([1, 3])

with col1:
    if st.button("📍 Share Google Maps Location"):
        # Mocking coordinates (In a real Flutter app, this comes from GPS)
        # Random location near Connaught Place, New Delhi
        lat = 28.6304 + (random.random() * 0.01) 
        lon = 77.2177 + (random.random() * 0.01)
        
        # Create Google Maps URL
        gmaps_url = f"https://www.google.com/maps?q={lat},{lon}"
        
        db = load_db()
        db['locations'][user] = {
            "lat": lat, 
            "lon": lon, 
            "url": gmaps_url, # Saving the link
            "time": datetime.now().strftime("%H:%M:%S")
        }
        save_db(db)
        st.success("Location sent!")

with col2:
    db = load_db()
    partner_loc = db['locations'].get(partner)
    
    if partner_loc:
        # Show Map Preview
        st.map({'lat': [partner_loc['lat']], 'lon': [partner_loc['lon']]}, zoom=15)
        
        # Show Timestamp
        st.caption(f"Last updated: {partner_loc['time']}")
        
        # Display Clickable Google Maps Button
        st.link_button(
            label="🗺️ Open in Google Maps", 
            url=partner_loc.get('url', '#')
        )
    else:
        st.info("Waiting for partner to share location...")

st.markdown("---")

# 2. Chat Module
st.subheader("💬 Private Chat")

# Load the database to check for keys
db = load_db()

# STATUS CHECK: Does the partner have a Public Key?
partner_has_key = 'keys' in db and partner in db['keys']

if partner_has_key:
    # --- SCENARIO 1: Partner is ready. Show Chat Input. ---
    with st.form("chat_form", clear_on_submit=True):
        msg_input = st.text_input("Type a message...")
        submitted = st.form_submit_button("Send Encrypted")
        
        if submitted and msg_input:
            # Get User B's Public Key
            partner_pub_key = db['keys'][partner]
            
            # Encrypt the message
            encrypted_payload = encrypt_message(msg_input, partner_pub_key)
            
            # Create Message Object
            msg_obj = {
                "from": user,
                "to": partner,
                "payload": encrypted_payload,
                "timestamp": datetime.now().strftime("%H:%M")
            }
            
            # Save to Database
            db['messages'].append(msg_obj)
            save_db(db)
            st.rerun() # Refresh immediately to show the sent message

else:
    # --- SCENARIO 2: Partner key is missing. Disable Chat. ---
    st.error(f"🚫 Cannot send message: **{partner}** has not logged in yet.")
    st.info(f"Ask **{partner}** to open this app in their browser to generate their Encryption Keys.")

# --- MESSAGE DISPLAY ---
chat_container = st.container()

with chat_container:
    # Filter messages for this conversation
    my_msgs = [m for m in db['messages'] if m['to'] == user or m['from'] == user]
    
    if not my_msgs:
        st.caption("No messages yet.")
    
    for msg in my_msgs:
        is_me = msg['from'] == user
        
        if is_me:
            # Message I sent
            with st.chat_message("user"):
                st.write("🔒 *[Encrypted Message Sent]*")
                st.caption(f"{msg['timestamp']} ✓")
        else:
            # Message I received
            decrypted_text = decrypt_message(msg['payload'], st.session_state['private_key'])
            with st.chat_message("assistant"):
                if "Error" in decrypted_text:
                    st.error("⚠️ Message could not be decrypted. Keys may have changed.")
                else:
                    st.write(decrypted_text)
                st.caption(f"From {partner} • {msg['timestamp']}")

# --- AUTO REFRESH LOOP ---
time.sleep(REFRESH_RATE)
st.rerun()
