#!/usr/bin/env python3
"""Preflight helpers for the manual "Publish release" workflow.

Subcommands (all inputs that originate from a user or a secret arrive via the
environment, never via shell interpolation):

  validate         VERSION_INPUT           -> tag/version/sequence (GITHUB_OUTPUT)
  check-binaries   --root --stage-dir      validate and stage the prebuilt binaries
  check-remote     GITHUB_REPOSITORY, TAG, SEQUENCE, GH_TOKEN
                                           refuse existing tag/release/older version
  write-key        NATIVE_UPDATE_PRIVATE_KEY_PEM, --dir
                                           write the signing key into a private dir
  verify-package   --package-dir --expected-sequence --expected-url
                   NATIVE_UPDATE_PUBLIC_KEY
                                           check the signed package before upload
  notes            TAG, VERSION, SEQUENCE, GITHUB_SHA, --output, --asset
                                           write the release notes
  verify-draft     GITHUB_REPOSITORY, TAG, GH_TOKEN, --asset
                                           confirm every asset reached the draft

The signing key is never logged. Nothing here writes to the remote repository.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys

VERSION_RE = re.compile(
    r"v?(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})(?:\.(0|[1-9][0-9]{0,5}))?", re.ASCII
)
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
MAJOR_SCALE = 10 ** 12
MINOR_SCALE = 10 ** 6

LOGIN_LIB = "libLogin.so"
LOADER_LIB = "libloader.so"
INJECTOR = "Injector"
MANIFEST = "native-manifest.txt"
PUBLIC_KEY = "public-key.txt"
MAX_NATIVE_SIZE = 134217728
SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)

ELF64_EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_PHDR_SIZE = 56
EM_AARCH64 = 183
ET_DYN = 3
PT_LOAD = 1

GH_TIMEOUT = 120


class PreflightError(Exception):
    """A user-facing failure whose message is safe to print."""


# --- version ------------------------------------------------------------------

class Version:
    def __init__(self, tag: str, major: int, minor: int, patch: int):
        self.tag = tag
        self.major = major
        self.minor = minor
        self.patch = patch

    @property
    def canonical(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @property
    def sequence(self) -> int:
        return self.major * MAJOR_SCALE + self.minor * MINOR_SCALE + self.patch


def parse_version(text: str) -> Version:
    m = VERSION_RE.fullmatch(text) if isinstance(text, str) else None
    if m is None:
        raise PreflightError(
            "version must look like 2.3 or v2.3.1 (MAJOR.MINOR[.PATCH], optional leading v, "
            "digits only, no leading zeros, each part 0..999999)"
        )
    # The regex caps each part at six digits, so every part is within 0..MAX_PART.
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    return Version(text, major, minor, patch)


def parse_release_version(text: str) -> Version:
    """Like parse_version, but a release must have a positive native-update sequence."""
    version = parse_version(text)
    if version.sequence == 0:
        raise PreflightError("version 0.0 has sequence 0; a release needs a positive sequence (e.g. 0.0.1)")
    return version


def try_parse_version(text: str):
    try:
        return parse_version(text)
    except PreflightError:
        return None


def write_outputs(path: str, values: dict) -> None:
    with open(path, "a", encoding="ascii") as f:
        for key, value in values.items():
            f.write(f"{key}={value}\n")


def cmd_validate(args) -> int:
    version = parse_release_version(os.environ.get("VERSION_INPUT", ""))
    values = {"tag": version.tag, "version": version.canonical, "sequence": version.sequence}
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        write_outputs(out, values)
    for key, value in values.items():
        print(f"{key}={value}")
    return 0


# --- binaries -----------------------------------------------------------------

def read_regular_file(path: str, what: str, limit: int = None) -> bytes:
    try:
        st = os.lstat(path)
    except OSError:
        raise PreflightError(f"{what} is missing ({os.path.basename(path)}); commit the prebuilt binary first") from None
    if not stat.S_ISREG(st.st_mode):
        raise PreflightError(f"{what} is not a regular file")
    if st.st_size == 0:
        raise PreflightError(f"{what} is empty")
    if limit is not None and st.st_size > limit:
        raise PreflightError(f"{what} is larger than {limit} bytes")
    with open(path, "rb") as f:
        return f.read()


def validate_arm64_elf(data: bytes, what: str) -> None:
    if len(data) < ELF64_EHDR.size:
        raise PreflightError(f"{what} is too small to be an ELF64 file")
    (ident, e_type, e_machine, e_version, _entry, phoff, _shoff, _flags,
     ehsize, phentsize, phnum, _shentsize, _shnum, _shstrndx) = ELF64_EHDR.unpack_from(data, 0)
    if ident[:4] != b"\x7fELF":
        raise PreflightError(f"{what} is not an ELF file")
    if ident[4] != 2 or ident[5] != 1:
        raise PreflightError(f"{what} is not little-endian ELF64")
    if e_type != ET_DYN:
        raise PreflightError(f"{what} is not a shared object (ET_DYN)")
    if e_machine != EM_AARCH64:
        raise PreflightError(f"{what} is not AArch64 (EM_AARCH64); build it for arm64-v8a")
    if ehsize != ELF64_EHDR.size or phentsize != ELF64_PHDR_SIZE or phnum == 0:
        raise PreflightError(f"{what} has a malformed ELF header")
    if phoff < ELF64_EHDR.size or phoff + phentsize * phnum > len(data):
        raise PreflightError(f"{what} program headers are outside the file")
    if not any(struct.unpack_from("<I", data, phoff + i * phentsize)[0] == PT_LOAD for i in range(phnum)):
        raise PreflightError(f"{what} has no PT_LOAD segment")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stage_binaries(root: str, stage_dir: str) -> dict:
    """Validate the prebuilt binaries and copy them into a fresh stage directory.

    Returns {name: sha256}. The stage copies are what gets signed and uploaded, so a
    root file changing between commands cannot desynchronise the release.
    """
    if os.path.lexists(stage_dir):
        raise PreflightError("stage directory already exists")
    contents = {
        LOGIN_LIB: read_regular_file(os.path.join(root, LOGIN_LIB), LOGIN_LIB),
        LOADER_LIB: read_regular_file(os.path.join(root, LOADER_LIB), LOADER_LIB, MAX_NATIVE_SIZE),
        INJECTOR: read_regular_file(os.path.join(root, INJECTOR), INJECTOR),
    }
    validate_arm64_elf(contents[LOGIN_LIB], LOGIN_LIB)
    validate_arm64_elf(contents[LOADER_LIB], LOADER_LIB)
    os.makedirs(stage_dir, mode=0o755)
    digests = {}
    for name, data in contents.items():
        path = os.path.join(stage_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o644)
        digests[name] = hashlib.sha256(data).hexdigest()
    return digests


def cmd_check_binaries(args) -> int:
    digests = stage_binaries(args.root, args.stage_dir)
    for name, digest in digests.items():
        print(f"{digest}  {name}")
    return 0


# --- GitHub (read-only, via gh) -----------------------------------------------

class GhResult:
    def __init__(self, returncode: int, stdout: str, stderr: str):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run_gh(args) -> GhResult:
    try:
        proc = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=GH_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        raise PreflightError("could not run the gh CLI") from None
    return GhResult(proc.returncode, proc.stdout, proc.stderr)


def _is_not_found(result: GhResult) -> bool:
    return "HTTP 404" in result.stderr


def _gh_lines(gh, args, what: str) -> list:
    result = gh(args)
    if result.returncode != 0:
        raise PreflightError(f"GitHub API call failed while trying to {what}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def tag_ref_exists(gh, repo: str, tag: str) -> bool:
    result = gh(["api", f"repos/{repo}/git/ref/tags/{tag}"])
    if result.returncode == 0:
        return True
    if _is_not_found(result):
        return False
    raise PreflightError("GitHub API call failed while trying to look up the tag")


def list_tag_names(gh, repo: str) -> list:
    return _gh_lines(gh, ["api", f"repos/{repo}/tags", "--paginate", "--jq", ".[].name"], "list tags")


def list_releases(gh, repo: str) -> list:
    jq = ".[] | {id, tag_name, draft, assets: [.assets[] | {name, size, digest}]}"
    records = []
    for line in _gh_lines(gh, ["api", f"repos/{repo}/releases", "--paginate", "--jq", jq], "list releases"):
        try:
            record = json.loads(line)
        except ValueError:
            raise PreflightError("unexpected output while listing releases") from None
        if not isinstance(record, dict) or not isinstance(record.get("tag_name"), str):
            raise PreflightError("unexpected output while listing releases")
        records.append(record)
    return records


def check_remote(gh, repo: str, version: Version) -> None:
    if not REPO_RE.fullmatch(repo or ""):
        raise PreflightError("GITHUB_REPOSITORY is missing or malformed")
    tag = version.tag
    releases = list_releases(gh, repo)
    tag_names = list_tag_names(gh, repo)

    if tag_ref_exists(gh, repo, tag) or tag in tag_names:
        raise PreflightError(f"tag {tag} already exists; refusing to overwrite it")
    for release in releases:
        if release["tag_name"] == tag:
            kind = "draft release" if release.get("draft") else "release"
            raise PreflightError(f"a {kind} for tag {tag} already exists; refusing to overwrite it")

    folded = tag.casefold()
    for name in [*tag_names, *(r["tag_name"] for r in releases)]:
        if name.casefold() == folded:
            raise PreflightError(f"{name} differs from {tag} only by case; refusing")

    newest = None
    for name in [*tag_names, *(r["tag_name"] for r in releases)]:
        other = try_parse_version(name)  # legacy date tags and anything else unparseable are skipped
        if other is not None and (newest is None or other.sequence > newest.sequence):
            newest = other
    if newest is not None and version.sequence <= newest.sequence:
        raise PreflightError(
            f"version sequence {version.sequence} is not newer than existing {newest.tag} "
            f"(sequence {newest.sequence}); equivalent spellings such as 2.2 and 2.2.0 are the same version"
        )


def cmd_check_remote(args) -> int:
    version = parse_release_version(os.environ.get("TAG", ""))
    declared = os.environ.get("SEQUENCE", "")
    if declared != str(version.sequence):
        raise PreflightError("SEQUENCE does not match TAG")
    check_remote(run_gh, os.environ.get("GITHUB_REPOSITORY", ""), version)
    print(f"{version.tag} is unused and newer than every existing version tag")
    return 0


def verify_draft(gh, repo: str, tag: str, expected: dict) -> int:
    """expected: {asset name: (size, sha256)}; the release must be a draft holding exactly these assets.

    Returns the draft's numeric release id.
    """
    matches = [r for r in list_releases(gh, repo) if r["tag_name"] == tag]
    if len(matches) != 1:
        raise PreflightError(f"expected exactly one release for {tag}, found {len(matches)}")
    release = matches[0]
    if not release.get("draft"):
        raise PreflightError(f"release {tag} is not a draft")
    uploaded = {a.get("name"): a for a in release.get("assets", [])}
    if set(uploaded) != set(expected):
        raise PreflightError(
            f"draft assets {sorted(n for n in uploaded if n)} do not match expected {sorted(expected)}"
        )
    for name, (size, digest) in expected.items():
        asset = uploaded[name]
        if asset.get("size") != size:
            raise PreflightError(f"uploaded {name} has the wrong size")
        remote_digest = asset.get("digest")
        if remote_digest and remote_digest != f"sha256:{digest}":
            raise PreflightError(f"uploaded {name} has the wrong sha256")
    release_id = release.get("id")
    if not isinstance(release_id, int) or release_id <= 0:
        raise PreflightError("draft release has no valid id")
    return release_id


def _expected_assets(paths) -> dict:
    expected = {}
    for path in paths:
        name = os.path.basename(path)
        if name in expected:
            raise PreflightError(f"duplicate asset name {name}")
        expected[name] = (os.path.getsize(path), sha256_file(path))
    return expected


def cmd_verify_draft(args) -> int:
    release_id = verify_draft(run_gh, os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("TAG", ""),
                              _expected_assets(args.asset))
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        write_outputs(out, {"release_id": release_id})
    print("draft release holds every expected asset")
    return 0


# --- signing key and package --------------------------------------------------

def write_private_key(env, directory: str) -> str:
    pem = env.get("NATIVE_UPDATE_PRIVATE_KEY_PEM", "")
    if not pem.strip():
        raise PreflightError("secret NATIVE_UPDATE_PRIVATE_KEY_PEM is not set; refusing to publish unsigned")
    if "-----BEGIN" not in pem or "PRIVATE KEY-----" not in pem:
        raise PreflightError("secret NATIVE_UPDATE_PRIVATE_KEY_PEM is not a PEM private key")
    os.umask(0o077)
    os.mkdir(directory, 0o700)
    path = os.path.join(directory, "private.pem")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(pem if pem.endswith("\n") else pem + "\n")
    return path


def cmd_write_key(args) -> int:
    write_private_key(os.environ, args.dir)
    print("signing key staged")
    return 0


def _strip_trailing_lf(text: str) -> str:
    return text[:-1] if text.endswith("\n") else text


def verify_package(package_dir: str, expected_sequence: int, expected_url: str, expected_public_key: str) -> None:
    names = sorted(os.listdir(package_dir))
    if names != sorted([LOADER_LIB, MANIFEST, PUBLIC_KEY]):
        raise PreflightError(f"unexpected package contents: {names}")
    if not expected_public_key.strip():
        raise PreflightError("repository variable NATIVE_UPDATE_PUBLIC_KEY is not set")
    with open(os.path.join(package_dir, PUBLIC_KEY), "rb") as f:
        generated = f.read().decode("ascii", "replace")
    if _strip_trailing_lf(generated) != _strip_trailing_lf(expected_public_key):
        raise PreflightError(
            "the signing key does not match repository variable NATIVE_UPDATE_PUBLIC_KEY; refusing to publish"
        )
    try:
        base64.b64decode(_strip_trailing_lf(generated), validate=True)
    except (binascii.Error, ValueError):
        raise PreflightError("generated public key is not valid base64") from None

    with open(os.path.join(package_dir, MANIFEST), "rb") as f:
        data = f.read()
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise PreflightError("manifest is not ASCII") from None
    lines = text.split("\n")
    if lines.pop() != "" or len(lines) != 9 or lines[0] != "WR-NATIVE-UPDATE/1":
        raise PreflightError("manifest does not follow the WR-NATIVE-UPDATE/1 layout")
    fields = {}
    for line, key in zip(lines[1:], ["sequence", "abi", "bootstrapApi", "minSdk", "size", "sha256", "url", "signature"]):
        if not line.startswith(key + "="):
            raise PreflightError(f"manifest field {key} missing or out of order")
        fields[key] = line[len(key) + 1:]
    loader = os.path.join(package_dir, LOADER_LIB)
    if fields["sequence"] != str(expected_sequence):
        raise PreflightError("manifest sequence does not match the release version")
    if fields["url"] != expected_url:
        raise PreflightError("manifest url does not match the release asset url")
    if fields["size"] != str(os.path.getsize(loader)):
        raise PreflightError("manifest size does not match libloader.so")
    if not SHA256_RE.fullmatch(fields["sha256"]) or fields["sha256"] != sha256_file(loader):
        raise PreflightError("manifest sha256 does not match libloader.so")


def cmd_verify_package(args) -> int:
    verify_package(args.package_dir, args.expected_sequence, args.expected_url,
                   os.environ.get("NATIVE_UPDATE_PUBLIC_KEY", ""))
    print("signed package matches the release and the pinned public key")
    return 0


# --- notes --------------------------------------------------------------------

def render_notes(version: Version, commit: str, assets: dict) -> str:
    lines = [
        "| Field | Value |",
        "| --- | --- |",
        f"| Version | `{version.tag}` |",
        f"| Native update sequence | `{version.sequence}` |",
        f"| Commit | `{commit}` |",
        "",
        "| Asset | SHA-256 |",
        "| --- | --- |",
    ]
    lines += [f"| `{name}` | `{digest}` |" for name, (_size, digest) in sorted(assets.items())]
    lines += [
        "",
        "The prebuilt binaries are committed, not built by this workflow. Their embedded "
        "AUTH_VER must be built to match this version.",
        "",
    ]
    return "\n".join(lines)


def cmd_notes(args) -> int:
    version = parse_release_version(os.environ.get("TAG", ""))
    commit = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise PreflightError("GITHUB_SHA is missing or malformed")
    notes = render_notes(version, commit, _expected_assets(args.asset))
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(notes)
    return 0


# --- cli ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate").set_defaults(func=cmd_validate)

    p = sub.add_parser("check-binaries")
    p.add_argument("--root", required=True)
    p.add_argument("--stage-dir", required=True)
    p.set_defaults(func=cmd_check_binaries)

    sub.add_parser("check-remote").set_defaults(func=cmd_check_remote)

    p = sub.add_parser("write-key")
    p.add_argument("--dir", required=True)
    p.set_defaults(func=cmd_write_key)

    p = sub.add_parser("verify-package")
    p.add_argument("--package-dir", required=True)
    p.add_argument("--expected-sequence", type=int, required=True)
    p.add_argument("--expected-url", required=True)
    p.set_defaults(func=cmd_verify_package)

    p = sub.add_parser("notes")
    p.add_argument("--output", required=True)
    p.add_argument("--asset", action="append", default=[], required=True)
    p.set_defaults(func=cmd_notes)

    p = sub.add_parser("verify-draft")
    p.add_argument("--asset", action="append", default=[], required=True)
    p.set_defaults(func=cmd_verify_draft)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PreflightError as exc:
        print(f"release_preflight.py: error: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print("release_preflight.py: error: file I/O error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
