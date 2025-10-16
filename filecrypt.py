import argparse
import os
from pathlib import Path
import binascii
from getpass import getpass
import json
import base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

print("[DEBUG] This is the correct filecrypt.py file!")

try:
    from argon2.low_level import hash_secret_raw, Type
    USE_ARGON2 = True
except ImportError:
    USE_ARGON2 = False


# --- HELPER FUNCTIONS (Task 2) ---

def derive_key_from_password(password: str, salt: bytes, length=32) -> bytes:
    """Derive a key from a password using Argon2 or PBKDF2."""
    password_bytes = password.encode()
    if USE_ARGON2:
        print("[i] Deriving key using Argon2...")
        key = hash_secret_raw(password_bytes, salt, time_cost=2, memory_cost=65536,
                              parallelism=2, hash_len=length, type=Type.ID)
    else:
        print("[i] Deriving key using PBKDF2 (Argon2 not installed).")
        key = PBKDF2(password_bytes, salt, dkLen=length, count=200_000)
    return key


def encrypt_file(filepath: Path, key: bytes):
    """Encrypt a file using AES-GCM (password mode – Task 2)."""
    with open(filepath, "rb") as f:
        plaintext = f.read()

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    enc_data = cipher.nonce + tag + ciphertext
    enc_path = filepath.with_suffix(filepath.suffix + ".enc")
    with open(enc_path, "wb") as ef:
        ef.write(enc_data)
    print(f"[+] Encrypted: {filepath} → {enc_path}")


def decrypt_file(filepath: Path, key: bytes):
    """Decrypt a file using AES-GCM (password mode – Task 2)."""
    with open(filepath, "rb") as f:
        data = f.read()

    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    dec_path = filepath.with_suffix(".dec")
    with open(dec_path, "wb") as df:
        df.write(plaintext)
    print(f"[+] Decrypted: {filepath} → {dec_path}")


# --- SHAMIR SECRET SHARING FUNCTIONS (Task 2) ---

def split_master_key(master_key: bytes, n: int, k: int):
    """Split a master key into n parts, requiring k to recover it."""
    shares = Shamir.split(k, n, master_key)
    share_texts = [f"{idx}:{binascii.hexlify(s).decode()}" for idx, s in shares]
    return share_texts


def recover_master_key_from_shares(share_texts):
    """Recover the master key from shares."""
    shares_for_combine = []
    for st in share_texts:
        idx_str, hexdata = st.split(":", 1)
        shares_for_combine.append((int(idx_str), binascii.unhexlify(hexdata)))
    master = Shamir.combine(shares_for_combine)
    return master


# --- COMMANDS (Task 2) ---

def cmd_init(args):
    """Create a new master key and split it using Shamir's Secret Sharing."""
    master_key = get_random_bytes(16)
    outdir = Path(args.outdir)
    outdir.mkdir(exist_ok=True)

    shares = split_master_key(master_key, args.n, args.k)
    for i, s in enumerate(shares, start=1):
        Path(outdir / f"share_{i}.txt").write_text(s)

    if args.save_master:
        Path(outdir / "master.key").write_bytes(master_key)
        print("[!] Master key saved (educational purpose only).")
    print(f"[+] Created {args.n} shares ({args.k} required to recover).")


def cmd_encrypt(args):
    """Encrypt a file using a password (Task 2)."""
    password = getpass("Password: ")
    salt = get_random_bytes(16)
    key = derive_key_from_password(password, salt)
    encrypt_file(Path(args.file), key)
    with open("salt.bin", "wb") as sf:
        sf.write(salt)
    print("[+] Salt saved to: salt.bin")


def cmd_decrypt(args):
    """Decrypt a file using a password (Task 2)."""
    password = getpass("Password: ")
    with open("salt.bin", "rb") as sf:
        salt = sf.read()
    key = derive_key_from_password(password, salt)
    decrypt_file(Path(args.file), key)


def cmd_recover(args):
    """Recover the master key from share files (Task 2)."""
    share_texts = [Path(p).read_text().strip() for p in args.share_files]
    master = recover_master_key_from_shares(share_texts)
    Path("recovered_master.key").write_bytes(master)
    print("[+] Master key recovered → recovered_master.key")


# ========== TASK 3: RSA HYBRID ENCRYPTION (NEW) ==========

def gen_rsa_keys(bits: int, outdir: Path, with_passphrase: bool):
    """Generate an RSA key pair (PKCS#8). The private key can be protected with a passphrase."""
    outdir.mkdir(parents=True, exist_ok=True)
    key = RSA.generate(bits)
    passphrase = None
    protection = None
    if with_passphrase:
        passphrase = getpass("Password to protect the private key (PEM): ")
        protection = "scryptAndAES128-CBC"

    private_pem = key.export_key(format='PEM', passphrase=passphrase, pkcs=8, protection=protection)
    public_pem = key.publickey().export_key()

    (outdir / "private.pem").write_bytes(private_pem)
    (outdir / "public.pem").write_bytes(public_pem)
    print(f"[OK] Generated RSA keys ({bits} bits) → {outdir/'public.pem'} (public), {outdir/'private.pem'} (private)")


def encrypt_file_hybrid_rsa(filepath: Path, public_pem_path: Path):
    """Hybrid encryption: AES-256-GCM for content + RSA-OAEP(SHA-256) for AES key wrapping."""
    public_key = RSA.import_key(Path(public_pem_path).read_bytes())
    rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

    data_key = get_random_bytes(32)

    data = Path(filepath).read_bytes()
    nonce = get_random_bytes(12)
    aes = AES.new(data_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes.encrypt_and_digest(data)

    wrapped_key = rsa_cipher.encrypt(data_key)

    header = {
        "magic": "FCR3",
        "version": 1,
        "scheme": "RSA-OAEP+AES-256-GCM",
        "oaep_hash": "SHA256",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
    }
    header_blob = (json.dumps(header, separators=(',', ':')) + "\n\n").encode("utf-8")
    out_blob = header_blob + ciphertext

    outpath = Path(str(filepath) + ".enc")
    outpath.write_bytes(out_blob)
    print(f"[+] Encrypted (RSA+AES hybrid): {filepath} → {outpath}")
    return outpath


def decrypt_file_hybrid_rsa(filepath: Path, private_pem_path: Path, ask_passphrase: bool):
    """Hybrid decryption: RSA-OAEP unwraps the AES key, AES-GCM decrypts the content."""
    blob = Path(filepath).read_bytes()
    try:
        header_str, ciphertext = blob.split(b"\n\n", 1)
    except ValueError:
        raise ValueError("Invalid file format: missing header")

    header = json.loads(header_str.decode("utf-8"))
    if header.get("magic") != "FCR3" or header.get("scheme") != "RSA-OAEP+AES-256-GCM":
        raise ValueError("Unsupported .enc file format")

    nonce = base64.b64decode(header["nonce"])
    tag = base64.b64decode(header["tag"])
    wrapped_key = base64.b64decode(header["wrapped_key"])

    passphrase = None
    if ask_passphrase:
        passphrase = getpass("Password for the private PEM key: ")

    private_key = RSA.import_key(Path(private_pem_path).read_bytes(), passphrase=passphrase)
    rsa_cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    data_key = rsa_cipher.decrypt(wrapped_key)

    aes = AES.new(data_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, tag)

    outpath = Path(str(filepath).replace(".enc", ""))
    outpath.write_bytes(plaintext)
    print(f"[+] Decrypted (RSA+AES hybrid): {filepath} → {outpath}")
    return outpath


# --- COMMANDS (Task 3) ---

def cmd_genrsa(args):
    gen_rsa_keys(bits=args.bits, outdir=Path(args.outdir), with_passphrase=args.with_passphrase)


def cmd_encrypt_rsa(args):
    encrypt_file_hybrid_rsa(Path(args.file), Path(args.public))


def cmd_decrypt_rsa(args):
    decrypt_file_hybrid_rsa(Path(args.file), Path(args.private), ask_passphrase=args.passphrase)


# --- MAIN FUNCTION (CLI) ---

def main():
    parser = argparse.ArgumentParser(description="Simple file encryption tool (AES-256-GCM + Shamir SSS + RSA Hybrid)")
    sub = parser.add_subparsers(dest="command")

    # ---- Task 2 ----
    p_init = sub.add_parser("init", help="Create a master key and split it into shares")
    p_init.add_argument("--n", type=int, required=True, help="total number of shares")
    p_init.add_argument("--k", type=int, required=True, help="minimum number of shares required for recovery")
    p_init.add_argument("--outdir", default="shares", help="directory to save the shares")
    p_init.add_argument("--save-master", action="store_true", help="save master key (educational only)")
    p_init.set_defaults(func=cmd_init)

    p_enc = sub.add_parser("encrypt", help="Encrypt a file using a password (AES-GCM + KDF)")
    p_enc.add_argument("file", help="path to file to encrypt")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt a file using a password (AES-GCM + KDF)")
    p_dec.add_argument("file", help="path to .enc file to decrypt")
    p_dec.set_defaults(func=cmd_decrypt)

    p_rec = sub.add_parser("recover", help="Recover master key from share files (Shamir)")
    p_rec.add_argument("share_files", nargs="+", help="paths to share files (at least k required)")
    p_rec.set_defaults(func=cmd_recover)

    # ---- Task 3 (RSA) ----
    p_gen = sub.add_parser("genrsa", help="Generate an RSA key pair")
    p_gen.add_argument("--bits", type=int, default=3072, help="key length (bits)")
    p_gen.add_argument("--outdir", default="keys", help="directory to save PEM keys")
    p_gen.add_argument("--with-passphrase", action="store_true", help="encrypt private key with passphrase")
    p_gen.set_defaults(func=cmd_genrsa)

    p_er = sub.add_parser("encrypt-rsa", help="Hybrid encryption: AES-256-GCM + RSA-OAEP(SHA-256)")
    p_er.add_argument("file", help="file to encrypt")
    p_er.add_argument("--public", default="keys/public.pem", help="path to public PEM key")
    p_er.set_defaults(func=cmd_encrypt_rsa)

    p_dr = sub.add_parser("decrypt-rsa", help="Hybrid decryption: RSA-OAEP + AES-256-GCM")
    p_dr.add_argument("file", help=".enc file to decrypt")
    p_dr.add_argument("--private", default="keys/private.pem", help="path to private PEM key")
    p_dr.add_argument("--passphrase", action="store_true", help="ask for PEM private key password (if encrypted)")
    p_dr.set_defaults(func=cmd_decrypt_rsa)

    args = parser.parse_args()
    if args.command:
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
