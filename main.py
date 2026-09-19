import base64
import struct
import requests
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend

GOOGLE_CT_LOG_URL = "https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1"

def get_signed_tree_head():
    url = f"{GOOGLE_CT_LOG_URL}/get-sth"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    print(f"[*] Connected to Google CT Log!")
    print(f"[*] Total Tree Size: {data['tree_size']:,}\n")
    return data['tree_size']

def parse_leaf_input(leaf_input_b64):
    """
    Parses the binary MerkleTreeLeaf structure (RFC 6962 Section 3.4).
    Extracts raw DER X.509 cert bytes from leaf_input or extra_data.
    """
    data = base64.b64decode(leaf_input_b64)
    if len(data) < 12:
        return None, []

    # Read log_entry_type (bytes 10..11)
    # 0 = x509_entry, 1 = precert_entry
    entry_type = struct.unpack(">H", data[10:12])[0]
    
    cert_bytes = None
    if entry_type == 0:
        # X509Entry: 3-byte length prefix followed by ASN.1 DER cert
        cert_len = int.from_bytes(data[12:15], byteorder='big')
        cert_bytes = data[15:15 + cert_len]
    elif entry_type == 1:
        # PrecertEntry: skip 32-byte issuer key hash, length prefix, etc.
        # For precerts, the actual cert bytes reside inside extra_data.
        pass

    if not cert_bytes:
        return None, []

    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        
        # Extract Common Name (CN)
        cn = "N/A"
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            cn = cn_attrs[0].value

        # Extract Subject Alternative Names (SANs)
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        return cn, sans
    except Exception:
        return None, []

def fetch_latest_entries(tree_size, count=50):
    start = max(0, tree_size - count)
    end = tree_size - 1

    url = f"{GOOGLE_CT_LOG_URL}/get-entries"
    params = {"start": start, "end": end}
    
    print(f"[*] Fetching entries range {start} -> {end}...")
    resp = requests.get(url, params=params, timeout=15)
    resp.raise_for_status()
    
    entries = resp.json().get("entries", [])
    
    for idx, entry in enumerate(entries):
        cn, sans = parse_leaf_input(entry["leaf_input"])
        print(f"\n--- Entry #{start + idx} ---")
        print(f"Common Name (CN): {cn}")
        print(f"All Domains (SANs): {sans}")

if __name__ == "__main__":
    tree_size = get_signed_tree_head()
    fetch_latest_entries(tree_size, count=50)