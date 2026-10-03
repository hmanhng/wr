"""Offline tests for the manual release workflow and its preflight helpers.

Run from the repository root:  python3 -m unittest discover -s .github/tests -v
No network access; gh is always faked.
"""

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GITHUB_DIR = os.path.dirname(HERE)
SCRIPTS = os.path.join(GITHUB_DIR, "scripts")
WORKFLOW = os.path.join(GITHUB_DIR, "workflows", "release.yml")
PREFLIGHT = os.path.join(SCRIPTS, "release_preflight.py")
PUBLISHER = os.path.join(SCRIPTS, "create-native-update.py")

spec = importlib.util.spec_from_file_location("release_preflight", PREFLIGHT)
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)


def make_elf(machine=183, e_type=3, with_load=True) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, e_type, machine, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1 if with_load else 4, 5, 0, 0, 0, 0, 0, 0x1000)
    return header + phdr + bytes(64)


def make_root(directory, loader=True, login=True, injector=True, loader_elf=None):
    if login:
        write(os.path.join(directory, "libLogin.so"), make_elf())
    if loader:
        write(os.path.join(directory, "libloader.so"), loader_elf if loader_elf is not None else make_elf())
    if injector:
        write(os.path.join(directory, "Injector"), make_elf())


def write(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


class FakeGh:
    """Stands in for run_gh; routes by API path."""

    def __init__(self, tags=(), releases=(), ref_exists=False, fail=None):
        self.tags = list(tags)
        self.releases = list(releases)
        self.ref_exists = ref_exists
        self.fail = fail  # substring of an API path that answers HTTP 500
        self.calls = []

    def __call__(self, args):
        self.calls.append(list(args))
        assert args[0] == "api"
        path = args[1]
        if self.fail and self.fail in path:
            return rp.GhResult(1, "", "gh: Server Error (HTTP 500)")
        if "/git/ref/tags/" in path:
            if self.ref_exists:
                return rp.GhResult(0, "{}", "")
            return rp.GhResult(1, "", "gh: Not Found (HTTP 404)")
        if path.endswith("/tags"):
            return rp.GhResult(0, "".join(t + "\n" for t in self.tags), "")
        if path.endswith("/releases"):
            return rp.GhResult(0, "".join(json.dumps(r) + "\n" for r in self.releases), "")
        raise AssertionError(f"unexpected gh call {args}")


REPO = "hmanhng/wr"


def release(tag, draft=False, assets=(), rid=7):
    return {"id": rid, "tag_name": tag, "draft": draft, "assets": list(assets)}


class VersionTests(unittest.TestCase):
    def test_valid_spellings_and_sequence(self):
        cases = {
            "2.3": (2, 3, 0, "2.3.0", 2 * 10 ** 12 + 3 * 10 ** 6),
            "v2.3.1": (2, 3, 1, "2.3.1", 2 * 10 ** 12 + 3 * 10 ** 6 + 1),
            "0.0": (0, 0, 0, "0.0.0", 0),
            "0.1.0": (0, 1, 0, "0.1.0", 10 ** 6),
            "999999.999999.999999": (999999, 999999, 999999, "999999.999999.999999",
                                     999999 * 10 ** 12 + 999999 * 10 ** 6 + 999999),
        }
        for text, (major, minor, patch, canonical, seq) in cases.items():
            with self.subTest(text):
                v = rp.parse_version(text)
                self.assertEqual((v.major, v.minor, v.patch, v.canonical, v.sequence), (major, minor, patch, canonical, seq))
                self.assertEqual(v.tag, text)

    def test_max_sequence_fits_java_long(self):
        self.assertLess(rp.parse_version("999999.999999.999999").sequence, 10 ** 18)
        self.assertLess(rp.parse_version("999999.999999.999999").sequence, 2 ** 63)

    def test_equivalent_spellings_share_sequence(self):
        seqs = {rp.parse_version(t).sequence for t in ("2.2", "2.2.0", "v2.2", "v2.2.0")}
        self.assertEqual(len(seqs), 1)

    def test_ordering(self):
        order = ["0.9", "1.0", "1.0.1", "1.1", "2.2", "2.2.1", "2.10", "10.0"]
        seqs = [rp.parse_version(t).sequence for t in order]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), len(seqs))

    def test_invalid(self):
        bad = [
            "", " 2.3", "2.3 ", "2.3\n", "2", "v2", "V2.3", "2.3.1.4", "2..3", ".2.3", "2.3.", "02.3", "2.03", "2.3.01",
            "-2.3", "+2.3", "2.3-rc1", "2.3\nGITHUB_ENV=x", "2.3;id", "2.3$(id)", "`id`", "../2.3", "2.3/x",
            "1000000.0", "0.1000000", "0.0.1000000", "٢.٣", "2.3\x00", "140726", "latest",
        ]
        for text in bad:
            with self.subTest(repr(text)):
                with self.assertRaises(rp.PreflightError):
                    rp.parse_version(text)

    def test_legacy_date_tags_are_not_versions(self):
        for tag in ("140726", "031025", "010125"):
            self.assertIsNone(rp.try_parse_version(tag))

    def test_release_version_rejects_zero_sequence_but_history_parses(self):
        for text in ("0.0", "0.0.0", "v0.0", "v0.0.0"):
            with self.subTest(text):
                self.assertEqual(rp.parse_version(text).sequence, 0)
                with self.assertRaisesRegex(rp.PreflightError, "positive sequence"):
                    rp.parse_release_version(text)
        self.assertEqual(rp.parse_release_version("0.0.1").sequence, 1)
        self.assertEqual(rp.parse_release_version("0.1").sequence, 10 ** 6)

    def test_validate_cli_rejects_zero_without_output(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out")
            for text in ("0.0", "0.0.0", "v0.0"):
                with self.subTest(text):
                    env = dict(os.environ, VERSION_INPUT=text, GITHUB_OUTPUT=out)
                    r = subprocess.run([sys.executable, PREFLIGHT, "validate"], env=env, capture_output=True, text=True)
                    self.assertEqual(r.returncode, 1)
                    self.assertIn("positive sequence", r.stderr)
                    self.assertFalse(os.path.exists(out))
            env = dict(os.environ, VERSION_INPUT="0.0.1", GITHUB_OUTPUT=out)
            r = subprocess.run([sys.executable, PREFLIGHT, "validate"], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out) as f:
                self.assertEqual(f.read().splitlines(), ["tag=0.0.1", "version=0.0.1", "sequence=1"])

    def test_check_remote_cli_rejects_zero_without_gh(self):
        with tempfile.TemporaryDirectory() as d:
            gh = os.path.join(d, "gh")
            marker = os.path.join(d, "gh-called")
            with open(gh, "w") as f:
                f.write(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
            os.chmod(gh, 0o755)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"], GITHUB_REPOSITORY=REPO,
                       TAG="0.0", SEQUENCE="0")
            r = subprocess.run([sys.executable, PREFLIGHT, "check-remote"], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertFalse(os.path.exists(marker))

    def test_validate_cli_writes_outputs_only_after_validation(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out")
            env = dict(os.environ, VERSION_INPUT="v2.3", GITHUB_OUTPUT=out)
            r = subprocess.run([sys.executable, PREFLIGHT, "validate"], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out) as f:
                self.assertEqual(f.read().splitlines(), ["tag=v2.3", "version=2.3.0", f"sequence={2 * 10 ** 12 + 3 * 10 ** 6}"])
            os.remove(out)
            env["VERSION_INPUT"] = "2.3\nsequence=1"
            r = subprocess.run([sys.executable, PREFLIGHT, "validate"], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertFalse(os.path.exists(out))


class BinaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = os.path.join(self.tmp, "root")
        os.mkdir(self.root)
        self.stage = os.path.join(self.tmp, "stage")

    def test_all_present_are_staged(self):
        make_root(self.root)
        digests = rp.stage_binaries(self.root, self.stage)
        self.assertEqual(sorted(digests), ["Injector", "libLogin.so", "libloader.so"])
        for name in digests:
            with open(os.path.join(self.stage, name), "rb") as f, open(os.path.join(self.root, name), "rb") as g:
                self.assertEqual(f.read(), g.read())

    def test_missing_loader_fails_clearly(self):
        make_root(self.root, loader=False)
        with self.assertRaisesRegex(rp.PreflightError, "libloader.so is missing"):
            rp.stage_binaries(self.root, self.stage)
        self.assertFalse(os.path.exists(self.stage))

    def test_missing_login_and_injector(self):
        make_root(self.root, login=False)
        with self.assertRaisesRegex(rp.PreflightError, "libLogin.so is missing"):
            rp.stage_binaries(self.root, self.stage)
        shutil.rmtree(self.root)
        os.mkdir(self.root)
        make_root(self.root, injector=False)
        with self.assertRaisesRegex(rp.PreflightError, "Injector is missing"):
            rp.stage_binaries(self.root, self.stage)

    def test_empty_loader(self):
        make_root(self.root, loader_elf=b"")
        with self.assertRaisesRegex(rp.PreflightError, "empty"):
            rp.stage_binaries(self.root, self.stage)

    def test_directory_and_symlink_rejected(self):
        make_root(self.root, loader=False)
        os.mkdir(os.path.join(self.root, "libloader.so"))
        with self.assertRaisesRegex(rp.PreflightError, "not a regular file"):
            rp.stage_binaries(self.root, self.stage)
        os.rmdir(os.path.join(self.root, "libloader.so"))
        write(os.path.join(self.tmp, "real.so"), make_elf())
        os.symlink(os.path.join(self.tmp, "real.so"), os.path.join(self.root, "libloader.so"))
        with self.assertRaisesRegex(rp.PreflightError, "not a regular file"):
            rp.stage_binaries(self.root, self.stage)

    def test_non_arm64_and_non_elf_rejected(self):
        for name, blob, message in (
            ("x86", make_elf(machine=62), "AArch64"),
            ("exec", make_elf(e_type=2), "ET_DYN"),
            ("noload", make_elf(with_load=False), "PT_LOAD"),
            ("text", b"#!/bin/sh\n" + bytes(80), "not an ELF"),
            ("short", b"\x7fELF", "too small"),
        ):
            with self.subTest(name):
                shutil.rmtree(self.root)
                os.mkdir(self.root)
                make_root(self.root, loader_elf=blob)
                with self.assertRaisesRegex(rp.PreflightError, message):
                    rp.stage_binaries(self.root, self.stage)
                shutil.rmtree(self.stage, ignore_errors=True)

    def test_login_lib_must_be_arm64(self):
        make_root(self.root)
        write(os.path.join(self.root, "libLogin.so"), make_elf(machine=3))
        with self.assertRaisesRegex(rp.PreflightError, "libLogin.so is not AArch64"):
            rp.stage_binaries(self.root, self.stage)


class RemoteTests(unittest.TestCase):
    def check(self, version, **kw):
        gh = FakeGh(**kw)
        rp.check_remote(gh, REPO, rp.parse_version(version))
        return gh

    def fails(self, version, pattern, **kw):
        with self.assertRaisesRegex(rp.PreflightError, pattern):
            self.check(version, **kw)

    def test_fresh_repo_and_legacy_date_tags_ok(self):
        self.check("2.3", tags=["140726", "031025", "junk"], releases=[release("140726")])

    def test_newer_than_existing_ok(self):
        self.check("2.3", tags=["v2.2.9", "2.2"], releases=[release("2.2")])

    def test_existing_tag_refused(self):
        self.fails("2.3", "already exists", tags=["2.3"])
        self.fails("2.3", "already exists", ref_exists=True)

    def test_existing_release_and_draft_refused(self):
        self.fails("2.3", "release for tag 2.3", releases=[release("2.3")])
        self.fails("2.3", "draft release", releases=[release("2.3", draft=True)])

    def test_case_variant_refused(self):
        self.fails("v2.3", "only by case", tags=["V2.3"])

    def test_equivalent_alias_refused(self):
        self.fails("2.2.0", "not newer", tags=["2.2"])
        self.fails("v2.2", "not newer", tags=["2.2.0"])
        self.fails("2.2", "not newer", releases=[release("v2.2.0", draft=True)])

    def test_older_refused(self):
        self.fails("2.1", "not newer", tags=["2.2"])
        self.fails("2.2.1", "not newer", tags=["2.3"])

    def test_api_errors_fail_closed(self):
        for part in ("/tags", "/releases"):
            with self.subTest(part):
                self.fails("2.3", "GitHub API call failed", fail=part)
        gh = FakeGh(fail="/git/ref/tags/")
        with self.assertRaisesRegex(rp.PreflightError, "GitHub API call failed"):
            rp.check_remote(gh, REPO, rp.parse_version("2.3"))

    def test_garbage_release_listing_fails_closed(self):
        class Bad(FakeGh):
            def __call__(self, args):
                if args[1].endswith("/releases"):
                    return rp.GhResult(0, "not json\n", "")
                return super().__call__(args)

        with self.assertRaisesRegex(rp.PreflightError, "unexpected output"):
            rp.check_remote(Bad(), REPO, rp.parse_version("2.3"))

    def test_bad_repo(self):
        with self.assertRaises(rp.PreflightError):
            rp.check_remote(FakeGh(), "nope", rp.parse_version("2.3"))

    def test_cli_with_fake_gh_executable(self):
        with tempfile.TemporaryDirectory() as d:
            gh = os.path.join(d, "gh")
            with open(gh, "w") as f:
                f.write(
                    "#!/bin/sh\n"
                    'case "$2" in\n'
                    "  */git/ref/tags/*) echo 'gh: Not Found (HTTP 404)' >&2; exit 1;;\n"
                    "  */tags) echo 2.2; echo 140726;;\n"
                    "  */releases) ;;\n"
                    "esac\n"
                )
            os.chmod(gh, 0o755)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"], GITHUB_REPOSITORY=REPO,
                       TAG="2.3", SEQUENCE=str(rp.parse_version("2.3").sequence))
            r = subprocess.run([sys.executable, PREFLIGHT, "check-remote"], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            env.update(TAG="2.2.0", SEQUENCE=str(rp.parse_version("2.2.0").sequence))
            r = subprocess.run([sys.executable, PREFLIGHT, "check-remote"], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("not newer", r.stderr)


class DraftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        path = os.path.join(self.tmp, "a.bin")
        write(path, b"abc")
        self.expected = rp._expected_assets([path])
        self.digest = self.expected["a.bin"][1]

    def test_ok_and_returns_id(self):
        asset = {"name": "a.bin", "size": 3, "digest": "sha256:" + self.digest}
        gh = FakeGh(releases=[release("2.3", draft=True, assets=[asset], rid=42)])
        self.assertEqual(rp.verify_draft(gh, REPO, "2.3", self.expected), 42)

    def test_missing_extra_wrong(self):
        good = {"name": "a.bin", "size": 3, "digest": None}
        cases = {
            "not draft": release("2.3", draft=False, assets=[good]),
            "missing": release("2.3", draft=True, assets=[]),
            "extra": release("2.3", draft=True, assets=[good, {"name": "b", "size": 1}]),
            "size": release("2.3", draft=True, assets=[{"name": "a.bin", "size": 4}]),
            "digest": release("2.3", draft=True, assets=[{"name": "a.bin", "size": 3, "digest": "sha256:" + "0" * 64}]),
        }
        for name, rel in cases.items():
            with self.subTest(name):
                with self.assertRaises(rp.PreflightError):
                    rp.verify_draft(FakeGh(releases=[rel]), REPO, "2.3", self.expected)
        with self.assertRaises(rp.PreflightError):
            rp.verify_draft(FakeGh(releases=[]), REPO, "2.3", self.expected)

    def test_notes(self):
        notes = rp.render_notes(rp.parse_version("v2.3.1"), "a" * 40, self.expected)
        self.assertIn("| Version | `v2.3.1` |", notes)
        self.assertIn(f"`{2 * 10 ** 12 + 3 * 10 ** 6 + 1}`", notes)
        self.assertIn("a" * 40, notes)
        self.assertIn("AUTH_VER", notes)
        self.assertIn(self.digest, notes)


class KeyAndPackageTests(unittest.TestCase):
    PEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        old = os.umask(0o022)
        self.addCleanup(os.umask, old)

    def test_key_written_private(self):
        d = os.path.join(self.tmp, "key")
        path = rp.write_private_key({"NATIVE_UPDATE_PRIVATE_KEY_PEM": self.PEM}, d)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path) as f:
            self.assertEqual(f.read(), self.PEM + "\n")

    def test_missing_or_bad_key_refused(self):
        for value in ("", "  \n", "not a key"):
            with self.subTest(repr(value)):
                d = os.path.join(self.tmp, "k" + str(abs(hash(value))))
                with self.assertRaises(rp.PreflightError):
                    rp.write_private_key({"NATIVE_UPDATE_PRIVATE_KEY_PEM": value}, d)
                self.assertFalse(os.path.exists(d))
        with self.assertRaises(rp.PreflightError):
            rp.write_private_key({}, os.path.join(self.tmp, "k2"))

    def test_key_value_never_in_error_output(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            os.environ["NATIVE_UPDATE_PRIVATE_KEY_PEM"] = "secret-material"
            try:
                code = rp.main(["write-key", "--dir", os.path.join(self.tmp, "k3")])
            finally:
                del os.environ["NATIVE_UPDATE_PRIVATE_KEY_PEM"]
        self.assertEqual(code, 1)
        self.assertNotIn("secret-material", buf.getvalue())

    def make_package(self, public_key="QUJD\n", **manifest_overrides):
        pkg = os.path.join(self.tmp, "pkg")
        os.mkdir(pkg)
        lib = make_elf()
        write(os.path.join(pkg, "libloader.so"), lib)
        write(os.path.join(pkg, "public-key.txt"), public_key.encode())
        import hashlib
        fields = {
            "sequence": "2000003000000", "abi": "arm64-v8a", "bootstrapApi": "1", "minSdk": "28",
            "size": str(len(lib)), "sha256": hashlib.sha256(lib).hexdigest(),
            "url": "https://github.com/hmanhng/wr/releases/download/2.3/libloader.so", "signature": "AAAA",
        }
        fields.update(manifest_overrides)
        text = "WR-NATIVE-UPDATE/1\n" + "".join(f"{k}={v}\n" for k, v in fields.items())
        write(os.path.join(pkg, "native-manifest.txt"), text.encode())
        return pkg

    URL = "https://github.com/hmanhng/wr/releases/download/2.3/libloader.so"

    def test_package_ok_and_trailing_lf_only(self):
        pkg = self.make_package()
        rp.verify_package(pkg, 2000003000000, self.URL, "QUJD")
        rp.verify_package(pkg, 2000003000000, self.URL, "QUJD\n")

    def test_public_key_mismatch_refused(self):
        pkg = self.make_package()
        for expected in ("QUJE", "", "QUJD\n\n", " QUJD", "QUJD\r\n"):
            with self.subTest(repr(expected)):
                with self.assertRaises(rp.PreflightError):
                    rp.verify_package(pkg, 2000003000000, self.URL, expected)

    def test_manifest_mismatches_refused(self):
        for override in ({"sequence": "1"}, {"url": "https://example.com/libloader.so"},
                         {"size": "1"}, {"sha256": "0" * 64}):
            with self.subTest(override):
                shutil.rmtree(os.path.join(self.tmp, "pkg"), ignore_errors=True)
                pkg = self.make_package(**override)
                with self.assertRaises(rp.PreflightError):
                    rp.verify_package(pkg, 2000003000000, self.URL, "QUJD")

    def test_unexpected_contents_refused(self):
        pkg = self.make_package()
        write(os.path.join(pkg, "extra"), b"x")
        with self.assertRaisesRegex(rp.PreflightError, "unexpected package contents"):
            rp.verify_package(pkg, 2000003000000, self.URL, "QUJD")


@unittest.skipUnless(shutil.which("openssl") and os.path.exists(PUBLISHER), "needs openssl and the vendored publisher")
class SigningDryRunTests(unittest.TestCase):
    """Throwaway key generated in a temp dir; nothing here touches a production key."""

    def test_publisher_output_passes_verify_package(self):
        with tempfile.TemporaryDirectory() as d:
            key = os.path.join(d, "private.pem")
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", key],
                           check=True, capture_output=True)
            lib = os.path.join(d, "libloader.so")
            write(lib, make_elf())
            pkg = os.path.join(d, "pkg")
            seq = rp.parse_version("2.3").sequence
            url = "https://github.com/hmanhng/wr/releases/download/2.3/libloader.so"
            r = subprocess.run([sys.executable, PUBLISHER, "--library", lib, "--sequence", str(seq), "--url", url,
                                "--private-key", key, "--output-dir", pkg, "--min-sdk", "28"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(pkg, "public-key.txt")) as f:
                public = f.read()
            rp.verify_package(pkg, seq, url, public.rstrip("\n"))
            with self.assertRaises(rp.PreflightError):
                rp.verify_package(pkg, seq, url, "AAAA")


def run_blocks(text):
    """Extract `run: |` block bodies from the workflow with a tiny indentation parser."""
    blocks = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:- )?run: \|\s*$", lines[i])
        if m:
            indent = len(m.group(1)) + (2 if lines[i].lstrip().startswith("- ") else 0)
            body = []
            i += 1
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                body.append(lines[i])
                i += 1
            blocks.append(("\n".join(body) + "\n"))
            continue
        i += 1
    return blocks


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(WORKFLOW, encoding="utf-8") as f:
            cls.text = f.read()

    def test_only_manual_trigger(self):
        on_block = re.search(r"^on:\n((?:[ \t]+.*\n|\n)+)", self.text, re.M).group(1)
        self.assertEqual(re.findall(r"^  (\w+):", on_block, re.M), ["workflow_dispatch"])
        for trigger in ("push", "pull_request", "schedule", "workflow_run", "release:"):
            self.assertNotRegex(self.text, rf"^\s*{trigger}")
        self.assertRegex(on_block, r"version:\n\s+description: .*\n\s+required: true\n\s+type: string")

    def test_concurrency_and_permissions(self):
        self.assertRegex(self.text, r"concurrency:\n  group: wr-release\n  cancel-in-progress: false")
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read\n")
        self.assertEqual(self.text.count("contents: write"), 1)
        self.assertNotRegex(self.text, r"(?m)^\s+(id-token|actions|packages|pull-requests):")

    def test_checkout_does_not_persist_credentials(self):
        self.assertRegex(self.text, r"actions/checkout@v4\n\s+with:\n\s+persist-credentials: false")

    def test_no_expression_interpolation_in_shell(self):
        blocks = run_blocks(self.text)
        self.assertGreaterEqual(len(blocks), 8)
        for block in blocks:
            self.assertNotIn("${{", block)

    def test_user_input_only_reaches_env(self):
        self.assertEqual(self.text.count("inputs.version"), 1)
        self.assertRegex(self.text, r"VERSION_INPUT: \$\{\{ inputs\.version \}\}")

    def test_secret_scoped_to_signing_step(self):
        self.assertEqual(self.text.count("secrets."), 1)
        step = self.text.split("- name: Sign libloader.so")[1].split("\n      - name:")[0]
        self.assertIn("secrets.NATIVE_UPDATE_PRIVATE_KEY_PEM", step)
        self.assertIn("unset NATIVE_UPDATE_PRIVATE_KEY_PEM", step)
        self.assertIn("trap", step)
        self.assertNotIn("echo", step)
        self.assertNotIn("set -x", self.text)
        self.assertIn("vars.NATIVE_UPDATE_PUBLIC_KEY", self.text)

    def test_signing_uses_vendored_publisher_with_contract_arguments(self):
        for fragment in ("python3 .github/scripts/create-native-update.py", '--sequence "$SEQUENCE"',
                         'releases/download/${TAG}/libloader.so"', '--output-dir "$RUNNER_TEMP/native-package"',
                         "--min-sdk 28"):
            self.assertIn(fragment, self.text)

    def test_draft_then_publish_ordering(self):
        create = self.text.index("gh release create")
        publish = self.text.index("--method PATCH")
        self.assertLess(self.text.index("check-remote"), self.text.index("Sign libloader.so"))
        self.assertLess(self.text.index("verify-package"), create)
        self.assertLess(create, self.text.index("verify-draft"))
        self.assertLess(self.text.index("verify-draft"), publish)
        self.assertIn("--draft", self.text)
        self.assertIn('--target "$GITHUB_SHA"', self.text)
        self.assertIn('--title "$TAG"', self.text)
        self.assertIn("make_latest=true", self.text)
        for forbidden in ("--clobber", "--force", "git push", "git tag", "softprops", "gh release delete", "gh release upload"):
            self.assertNotIn(forbidden, self.text)

    def test_all_five_assets_uploaded(self):
        create = self.text[self.text.index("gh release create"):self.text.index("Verify draft assets")]
        for asset in ('"$stage/libLogin.so"', '"$stage/Injector"', '"$pkg/libloader.so"',
                      '"$pkg/native-manifest.txt"', '"$pkg/public-key.txt"'):
            self.assertIn(asset, create)

    def test_run_blocks_parse_with_bash(self):
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        for i, block in enumerate(run_blocks(self.text)):
            with self.subTest(block=i):
                r = subprocess.run([bash, "-n"], input=block, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_pyyaml_structure_if_available(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        data = yaml.safe_load(self.text)
        triggers = data.get(True, data.get("on"))  # PyYAML (YAML 1.1) turns the key `on` into True
        self.assertEqual(list(triggers), ["workflow_dispatch"])
        self.assertTrue(triggers["workflow_dispatch"]["inputs"]["version"]["required"])
        self.assertEqual(data["jobs"]["publish"]["permissions"], {"contents": "write"})
        self.assertEqual(data["permissions"], {"contents": "read"})
        self.assertIs(data["concurrency"]["cancel-in-progress"], False)


if __name__ == "__main__":
    unittest.main()
