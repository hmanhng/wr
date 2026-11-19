#!/usr/bin/env python3
"""Package a signed native-update release (offline; no network, no upload).

Produces <output-dir>/{libloader.so, native-manifest.txt, public-key.txt}.
The manifest is the WR-NATIVE-UPDATE/1 contract: nine LF-terminated ASCII lines,
the last one being a SHA256withRSA (PKCS#1 v1.5) signature over the first eight
lines (including their trailing LF). The private key is only passed to the
openssl CLI by path; it is never read, copied, or logged by this script.
"""

import argparse
import base64
import binascii
import hashlib
import ipaddress
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

MANIFEST_MAGIC = "WR-NATIVE-UPDATE/1"
ABI = "arm64-v8a"
BOOTSTRAP_API = "1"
MAX_SEQUENCE = 9223372036854775807
MAX_SIZE = 134217728
MAX_MANIFEST_BYTES = 8192
MIN_SDK_FLOOR = 28
MIN_SDK_CEIL = 10000
MIN_RSA_BITS = 3072
LIB_NAME = "libloader.so"
MANIFEST_NAME = "native-manifest.txt"
PUBLIC_KEY_NAME = "public-key.txt"
OPENSSL_TIMEOUT = 60

ELF64_EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_PHDR = struct.Struct("<IIQQQQQQ")
EM_AARCH64 = 183
ET_DYN = 3
PT_LOAD = 1

_DEC = re.compile(r"[1-9][0-9]*", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
MAX_URL_LENGTH = 2048  # UrlPolicy.MAX_URL_LENGTH on the consumer side
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", re.ASCII)
_IPV4 = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})", re.ASCII)
_IPV6_CHARS = re.compile(r"[0-9A-Fa-f:.]+", re.ASCII)
_PORT = re.compile(r"[0-9]{1,5}", re.ASCII)
# RFC 2396 path as java.net.URI parses it: pchar plus '/', escapes need two hex digits ('[' ']' are illegal).
_PATH = re.compile(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/]|%[0-9A-Fa-f]{2})+", re.ASCII)
# SPKI AlgorithmIdentifier OID rsaEncryption 1.2.840.113549.1.1.1
_RSA_OID = bytes.fromhex("2a864886f70d010101")


class UpdateError(Exception):
    """A user-facing failure whose message is safe to print."""


# --- validation ---------------------------------------------------------------

def parse_sequence(text: str) -> int:
    if not _DEC.fullmatch(text):
        raise UpdateError("--sequence must be a canonical positive decimal integer (no sign, no leading zero)")
    value = int(text)
    if value > MAX_SEQUENCE:
        raise UpdateError("--sequence exceeds 9223372036854775807")
    return value


def parse_min_sdk(text: str) -> int:
    if not _DEC.fullmatch(text):
        raise UpdateError("--min-sdk must be a canonical decimal integer (no sign, no leading zero)")
    value = int(text)
    if not MIN_SDK_FLOOR <= value <= MIN_SDK_CEIL:
        raise UpdateError(f"--min-sdk must be in {MIN_SDK_FLOOR}..{MIN_SDK_CEIL}")
    return value


def _valid_host(host: str) -> bool:
    """Same host rules as java.net.URI server authorities (what UrlPolicy.java accepts)."""
    if host.startswith("["):
        inner = host[1:-1]
        if not host.endswith("]") or not _IPV6_CHARS.fullmatch(inner):
            return False
        try:
            ipaddress.IPv6Address(inner)
        except ValueError:
            return False
        return True
    m = _IPV4.fullmatch(host)
    if m:
        return all(int(g) <= 255 for g in m.groups())
    if host.endswith("."):
        host = host[:-1]
    labels = host.split(".")
    # Every label alphanumeric/hyphen without a leading or trailing hyphen; the last label starts with a letter.
    return all(_LABEL.fullmatch(label) for label in labels) and labels[-1][0].isalpha()


def validate_url(url: str) -> str:
    """Strict absolute HTTPS URL, a subset of what UrlPolicy.java accepts.

    Also: at most 2048 characters, no query, and the last path segment must be libloader.so.
    """
    if not url or len(url) > MAX_URL_LENGTH or not url.isascii() or any(c <= " " or c == "\x7f" for c in url):
        raise UpdateError(f"--url must be an ASCII URI of at most {MAX_URL_LENGTH} characters without whitespace or control characters")
    if not url.startswith("https://"):
        raise UpdateError("--url must start with https://")
    if "#" in url:
        raise UpdateError("--url must not contain a fragment")
    if "?" in url:
        raise UpdateError("--url must not contain a query string (use a permanent asset URL)")
    rest = url[len("https://"):]
    authority, slash, path = rest.partition("/")
    path = slash + path
    if "@" in authority:
        raise UpdateError("--url must not contain userinfo")
    port = None  # None: no port given
    if authority.startswith("["):
        close = authority.find("]")
        host, tail = (authority[:close + 1], authority[close + 1:]) if close > 0 else (authority, "")
        if tail:
            if not tail.startswith(":"):
                raise UpdateError("--url has an invalid host")
            port = tail[1:]
    else:
        host, colon, tail = authority.partition(":")
        if colon:
            port = tail
    if not host or not _valid_host(host):
        raise UpdateError("--url has an invalid host")
    if port is not None and (not _PORT.fullmatch(port) or int(port) > 65535):
        raise UpdateError("--url has an invalid port")
    if not _PATH.fullmatch(path) or not path.startswith("/"):
        raise UpdateError("--url has an invalid path")
    if path.rsplit("/", 1)[-1] != LIB_NAME:
        raise UpdateError(f"--url path must end with /{LIB_NAME} (the file you upload)")
    return url


def validate_elf(data: bytes) -> None:
    if len(data) == 0:
        raise UpdateError("library is empty")
    if len(data) > MAX_SIZE:
        raise UpdateError(f"library is larger than {MAX_SIZE} bytes")
    if len(data) < ELF64_EHDR.size:
        raise UpdateError("library is too small to be an ELF64 file")
    (ident, e_type, e_machine, e_version, _entry, phoff, _shoff, _flags,
     ehsize, phentsize, phnum, _shentsize, _shnum, _shstrndx) = ELF64_EHDR.unpack_from(data, 0)
    if ident[:4] != b"\x7fELF":
        raise UpdateError("library is not an ELF file")
    if ident[4] != 2:
        raise UpdateError("library is not ELF64")
    if ident[5] != 1:
        raise UpdateError("library is not little-endian")
    if ident[6] != 1 or e_version != 1:
        raise UpdateError("library has an unsupported ELF version")
    if e_type != ET_DYN:
        raise UpdateError("library is not a shared object (ET_DYN)")
    if e_machine != EM_AARCH64:
        raise UpdateError("library is not AArch64 (EM_AARCH64)")
    if ehsize != ELF64_EHDR.size or phentsize != ELF64_PHDR.size or phnum == 0:
        raise UpdateError("library has a malformed ELF header")
    if phoff < ELF64_EHDR.size or phoff + phentsize * phnum > len(data):
        raise UpdateError("library program headers are outside the file")
    has_load = any(
        ELF64_PHDR.unpack_from(data, phoff + i * phentsize)[0] == PT_LOAD for i in range(phnum)
    )
    if not has_load:
        raise UpdateError("library has no PT_LOAD segment")


def read_library(path: str) -> bytes:
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            raise UpdateError("--library is not a regular file")
        if st.st_size > MAX_SIZE:
            raise UpdateError(f"library is larger than {MAX_SIZE} bytes")
        with open(path, "rb") as f:
            data = f.read(MAX_SIZE + 1)
    except OSError:
        raise UpdateError("cannot read --library") from None
    validate_elf(data)
    return data


# --- openssl ------------------------------------------------------------------

def find_openssl(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise UpdateError("openssl CLI not found; install OpenSSL or pass --openssl PATH")
    return found


def run_openssl(openssl: str, args: list, what: str) -> bytes:
    """Run openssl without a shell, stdin closed, detached from any tty (no prompts)."""
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        proc = subprocess.run(
            [openssl, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=OPENSSL_TIMEOUT,
            start_new_session=True,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise UpdateError(f"openssl timed out while trying to {what}") from None
    except OSError:
        raise UpdateError("cannot execute openssl") from None
    if proc.returncode != 0:
        raise UpdateError(f"openssl failed to {what}")
    return proc.stdout


def _der_read(data: bytes, pos: int, tag: int):
    """Read one DER TLV with the expected tag; return (value_start, value_end)."""
    if pos + 2 > len(data) or data[pos] != tag:
        raise ValueError("unexpected DER tag")
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise ValueError("DER overruns input")
    return pos, pos + length


def rsa_bits_from_spki(spki: bytes) -> int:
    """Return the modulus bit length of an RSA (rsaEncryption) SPKI, else raise UpdateError."""
    try:
        s, e = _der_read(spki, 0, 0x30)
        if e != len(spki):
            raise ValueError("trailing data")
        a_s, a_e = _der_read(spki, s, 0x30)
        o_s, o_e = _der_read(spki, a_s, 0x06)
        if spki[o_s:o_e] != _RSA_OID:
            raise UpdateError("private key is not an RSA key")
        b_s, b_e = _der_read(spki, a_e, 0x03)
        if spki[b_s] != 0:
            raise ValueError("bad bit string")
        k_s, k_e = _der_read(spki, b_s + 1, 0x30)
        n_s, n_e = _der_read(spki, k_s, 0x02)
        x_s, x_e = _der_read(spki, n_e, 0x02)
        modulus = int.from_bytes(spki[n_s:n_e], "big")
        exponent = int.from_bytes(spki[x_s:x_e], "big")
    except ValueError:
        raise UpdateError("cannot parse the derived public key") from None
    if exponent < 65537 or exponent % 2 == 0:
        raise UpdateError("RSA public exponent is too small or even")
    return modulus.bit_length()


def derive_public_key(openssl: str, key_path: str) -> bytes:
    try:
        with open(key_path, "rb") as f:
            head = f.read(4096)
    except OSError:
        raise UpdateError("cannot read --private-key") from None
    if b"ENCRYPTED" in head:
        raise UpdateError("encrypted private keys are not supported; use an unencrypted key kept in a protected location")
    # -passin pass: (empty) makes an unexpectedly encrypted key fail instead of prompting.
    spki = run_openssl(
        openssl,
        ["pkey", "-in", key_path, "-passin", "pass:", "-pubout", "-outform", "DER"],
        "read the private key (must be an unencrypted RSA key)",
    )
    bits = rsa_bits_from_spki(spki)
    if bits < MIN_RSA_BITS:
        raise UpdateError(f"RSA key is {bits} bits; at least {MIN_RSA_BITS} are required")
    return spki


def sign(openssl: str, key_path: str, work: str, signed_bytes: bytes) -> bytes:
    msg = os.path.join(work, "signed.txt")
    sig = os.path.join(work, "signature.bin")
    with open(msg, "wb") as f:
        f.write(signed_bytes)
    run_openssl(openssl, ["dgst", "-sha256", "-sign", key_path, "-passin", "pass:", "-out", sig, msg],
                "sign the manifest")
    with open(sig, "rb") as f:
        return f.read()


def verify(openssl: str, spki: bytes, work: str, signed_bytes: bytes, signature: bytes) -> None:
    pub = os.path.join(work, "public.der")
    msg = os.path.join(work, "verify.txt")
    sig = os.path.join(work, "verify.sig")
    for path, content in ((pub, spki), (msg, signed_bytes), (sig, signature)):
        with open(path, "wb") as f:
            f.write(content)
    run_openssl(openssl, ["dgst", "-sha256", "-verify", pub, "-keyform", "DER", "-signature", sig, msg],
                "verify the manifest signature")


# --- manifest -----------------------------------------------------------------

def build_manifest_head(sequence: int, min_sdk: int, size: int, sha256: str, url: str) -> bytes:
    lines = [
        MANIFEST_MAGIC,
        f"sequence={sequence}",
        f"abi={ABI}",
        f"bootstrapApi={BOOTSTRAP_API}",
        f"minSdk={min_sdk}",
        f"size={size}",
        f"sha256={sha256}",
        f"url={url}",
    ]
    return "".join(line + "\n" for line in lines).encode("ascii")


def parse_manifest(data: bytes) -> dict:
    """Strict contract parser; returns fields plus 'signed' (first 8 lines) and 'signature'."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise UpdateError("manifest exceeds 8192 bytes")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise UpdateError("manifest is not ASCII") from None
    if not text.endswith("\n") or "\r" in text:
        raise UpdateError("manifest must be LF-terminated")
    lines = text[:-1].split("\n")
    if len(lines) != 9 or lines[0] != MANIFEST_MAGIC:
        raise UpdateError("manifest must have the header and eight fields")
    fields = {}
    for line, key in zip(lines[1:], ["sequence", "abi", "bootstrapApi", "minSdk", "size", "sha256", "url", "signature"]):
        prefix = key + "="
        if not line.startswith(prefix):
            raise UpdateError(f"manifest field {key} missing or out of order")
        fields[key] = line[len(prefix):]
    parse_sequence(fields["sequence"])
    parse_min_sdk(fields["minSdk"])
    if fields["abi"] != ABI or fields["bootstrapApi"] != BOOTSTRAP_API:
        raise UpdateError("manifest abi/bootstrapApi mismatch")
    if not _DEC.fullmatch(fields["size"]) or int(fields["size"]) > MAX_SIZE:
        raise UpdateError("manifest size is invalid")
    if not _SHA256.fullmatch(fields["sha256"]):
        raise UpdateError("manifest sha256 is invalid")
    validate_url(fields["url"])
    try:
        fields["signature_raw"] = base64.b64decode(fields["signature"], validate=True)
    except (binascii.Error, ValueError):
        raise UpdateError("manifest signature is not valid base64") from None
    fields["signed"] = ("\n".join(lines[:8]) + "\n").encode("ascii")
    return fields


# --- packaging ----------------------------------------------------------------

def package(library: str, sequence: int, url: str, private_key: str, output_dir: str,
            min_sdk: int, openssl: str) -> dict:
    out = os.path.abspath(output_dir)
    parent = os.path.dirname(out)
    if os.path.lexists(out):
        raise UpdateError("--output-dir already exists; choose a new directory")
    if not os.path.isdir(parent):
        raise UpdateError("parent of --output-dir does not exist")
    if not os.path.isfile(private_key):
        raise UpdateError("--private-key is not a readable file")

    data = read_library(library)
    spki = derive_public_key(openssl, private_key)
    key_bytes = (rsa_bits_from_spki(spki) + 7) // 8

    staging = tempfile.mkdtemp(prefix=".native-update-staging-", dir=parent)
    try:
        lib_out = os.path.join(staging, LIB_NAME)
        with open(lib_out, "wb") as f:
            f.write(data)
        # Hash what was actually staged so a source file changing mid-run cannot desync the manifest.
        with open(lib_out, "rb") as f:
            staged = f.read(MAX_SIZE + 1)
        if staged != data:
            raise UpdateError("staged library differs from the source; aborting")
        validate_elf(staged)
        sha256 = hashlib.sha256(staged).hexdigest()

        head = build_manifest_head(sequence, min_sdk, len(staged), sha256, url)
        with tempfile.TemporaryDirectory(prefix="wr-native-sign-") as work:
            signature = sign(openssl, private_key, work, head)
            if len(signature) != key_bytes:
                raise UpdateError("unexpected signature length from openssl")
            manifest = head + b"signature=" + base64.b64encode(signature) + b"\n"
            if len(manifest) > MAX_MANIFEST_BYTES:
                raise UpdateError("manifest exceeds 8192 bytes")
            manifest_path = os.path.join(staging, MANIFEST_NAME)
            with open(manifest_path, "wb") as f:
                f.write(manifest)
            # Re-read what will be published and verify it end to end.
            with open(manifest_path, "rb") as f:
                parsed = parse_manifest(f.read())
            if parsed["signed"] != head or parsed["sha256"] != sha256:
                raise UpdateError("written manifest does not match the expected content")
            verify(openssl, spki, work, parsed["signed"], parsed["signature_raw"])

        with open(os.path.join(staging, PUBLIC_KEY_NAME), "wb") as f:
            f.write(base64.b64encode(spki) + b"\n")
        for name in (LIB_NAME, MANIFEST_NAME, PUBLIC_KEY_NAME):
            os.chmod(os.path.join(staging, name), 0o644)
        os.chmod(staging, 0o755)
        os.rename(staging, out)
        staging = None
    except OSError:
        raise UpdateError("file I/O error while packaging") from None
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
    return {"sequence": sequence, "size": len(data), "sha256": sha256}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Create a signed WR-NATIVE-UPDATE/1 release package (local only).")
    p.add_argument("--library", required=True, help="path to the arm64-v8a libloader.so to publish")
    p.add_argument("--sequence", required=True, help="monotonic release sequence (positive integer)")
    p.add_argument("--url", required=True, help="HTTPS URL of the uploaded libloader.so (e.g. a versioned GitHub release asset)")
    p.add_argument("--private-key", required=True, help="path to the offline unencrypted RSA (>=3072 bit) signing key")
    p.add_argument("--output-dir", required=True, help="new directory to create; must not exist")
    p.add_argument("--min-sdk", default=str(MIN_SDK_FLOOR), help="minimum Android SDK (default 28)")
    p.add_argument("--openssl", default="openssl", help="openssl executable (default: from PATH)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        sequence = parse_sequence(args.sequence)
        min_sdk = parse_min_sdk(args.min_sdk)
        url = validate_url(args.url)
        openssl = find_openssl(args.openssl)
        info = package(args.library, sequence, url, args.private_key, args.output_dir, min_sdk, openssl)
    except UpdateError as exc:
        print(f"create-native-update.py: error: {exc}", file=sys.stderr)
        return 1
    print(f"Created native update package: sequence={info['sequence']} size={info['size']} sha256={info['sha256']}")
    print("Upload libloader.so to the URL first, then publish native-manifest.txt. Nothing was uploaded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
