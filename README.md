# wr

This repository hosts the prebuilt binaries and the native-update feed (GitHub Releases) for the app.
Nothing here is built by CI: the binaries are committed, and the release workflow only validates,
signs and publishes them.

## Releasing

Releases are manual. No push, pull request or schedule triggers the workflow.

### Prerequisites

1. Build the binaries elsewhere (the sources are not in this repository) for `arm64-v8a`, with
   the embedded `AUTH_VER` equal to the version you are about to release. The workflow cannot check
   this; it only prints a warning.
2. Copy these three files to the **repository root** and commit them to the branch you will release from:
   - `libLogin.so` (AArch64 ELF shared object)
   - `libloader.so` (AArch64 ELF shared object; the signed native-update payload)
   - `Injector`

   The workflow fails clearly if any of them is missing, empty, not a regular file, or (for the two
   libraries) not an AArch64 ELF shared object. It never creates placeholders.
3. Configure signing once (see [Signing key setup](#signing-key-setup)).

### Publishing

1. Open **Actions → Publish release → Run workflow**.
2. Pick the branch/commit to release from. The release tag points at exactly that commit.
3. Enter `version` exactly as you want the tag and release title, e.g. `2.3` or `v2.3.1`.
   The tag and title are the input verbatim, so `2.3` and `v2.3` are different tags.

The workflow then:

1. validates the version and computes the native-update sequence,
2. validates and stages the three binaries,
3. refuses to continue if the tag or a (draft) release already exists, or if the version is not newer
   than every existing version tag,
4. signs `libloader.so` with the repository secret and checks the result against the pinned public key,
5. creates a **draft** release with all five assets,
6. verifies the draft holds every asset with the expected size, then publishes it as the latest release.

A failed run leaves any draft in place for inspection; nothing is deleted or overwritten. Delete the
draft yourself before retrying the same version.

Assets: `libLogin.so`, `libloader.so` (the staged copy that was signed), `Injector`,
`native-manifest.txt`, `public-key.txt`.

### Version format and sequence

`[v]MAJOR.MINOR[.PATCH]`: decimal digits only, no leading zeros (except a lone `0`), each part
`0..999999`. A missing patch is `0`. `0.0` (sequence 0) is refused as a release version; use `0.0.1` or higher.

```
sequence = major * 10^12 + minor * 10^6 + patch
```

For example `2.3` and `2.3.0` both give `2000003000000` and `v2.3.1` gives `2000003000001`. The maximum,
`999999.999999.999999`, is below `10^18`, so it fits a Java `long`. Equivalent spellings share a
sequence and are not release aliases: once `2.2` exists, `2.2.0` is refused. Legacy date-only tags
(for example `140726`) are ignored by the ordering check.

The `sequence` the app's bootstrap config compares against must use this same formula. Releasing a
build is separate from releasing a version: the committed binaries decide what the app runs; the
workflow only publishes them under the version you type.

### Native-update feed

Clients read one fixed URL, which GitHub redirects (at most 5 HTTPS redirects are allowed by the client) to the latest release:

```
https://github.com/hmanhng/wr/releases/latest/download/native-manifest.txt
```

The manifest (`WR-NATIVE-UPDATE/1`) is signed with RSA PKCS#1 v1.5 / SHA-256 and points at
`https://github.com/hmanhng/wr/releases/download/<tag>/libloader.so`. The client verifies it against
a public key pinned in the app. `public-key.txt` is only for operator bootstrap; the app must never
trust a downloaded public key.

### Signing key setup

The key is never committed. Do this once, offline:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem   # unencrypted, >= 3072 bits
openssl pkey -in private.pem -pubout -outform DER | base64 -w0                  # SPKI, base64
```

1. Store the contents of `private.pem` as the repository **secret** `NATIVE_UPDATE_PRIVATE_KEY_PEM`
   (Settings → Secrets and variables → Actions).
2. Store the base64 SPKI line as the repository **variable** `NATIVE_UPDATE_PUBLIC_KEY`. The workflow
   refuses to publish unless the key it signed with derives exactly this value (only a trailing
   newline is ignored).
3. Pin the same public key in the app's Gradle/bootstrap configuration, outside this repository.
4. Keep `private.pem` somewhere safe and delete stray copies. If the secret or variable is missing,
   or the keys differ, the run fails; there is no unsigned fallback.

### Local checks

```sh
python3 -m unittest discover -s .github/tests -v
```

These run offline with a faked `gh`; they do not contact GitHub or use any production key.
