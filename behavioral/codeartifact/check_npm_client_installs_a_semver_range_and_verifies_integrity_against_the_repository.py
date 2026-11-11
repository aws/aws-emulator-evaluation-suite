"""npm-client-installs-a-semver-range-and-verifies-integrity-against-the-repository."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "npm-client-installs-a-semver-range-and-verifies-integrity-against-the-repository"
GROUP = "package-endpoint"
SERVICES = ["codeartifact"]

#: Per-subprocess ceiling. A hung npm must fail the check, never hang the suite.
_NPM_TIMEOUT_SECONDS = 120.0

#: Published in this order. The range ^1.0.0 must resolve to 1.2.0: not the highest overall (2.0.0),
#: not the lowest matching (1.0.0), and not the last published (2.0.0).
_VERSIONS = ("1.0.0", "1.2.0", "2.0.0")
_RANGE = "^1.0.0"
_EXPECTED = "1.2.0"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The real npm client resolves a semver range against the repository, installs the version it
    chose, and the lockfile integrity matches the sha512 of the bytes CodeArtifact stores.

    Reference: https://docs.aws.amazon.com/codeartifact/latest/ug/npm-auth.html"""
    from fidelity_tests_runner import require_tools

    require_tools("npm", "node")

    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-dom-")
    repository = ctx.unique_name("sim2real-ca-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, repository))

    token = ca.get_authorization_token(domain=domain,
                                       durationSeconds=43200)["authorizationToken"]
    endpoint = ctx.endpoint_url(ca.get_repository_endpoint(domain=domain, repository=repository,
                                                           format="npm")["repositoryEndpoint"])

    workdir = tempfile.mkdtemp(prefix="sim2real-npm-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    npmrc = os.path.join(workdir, "npmrc")
    _write_npmrc(npmrc, endpoint, token)
    env = _npm_env(ctx, workdir, npmrc, endpoint)

    package = ctx.unique_name("sim2real-npmcli-")
    ctx.on_cleanup(lambda: _delete_package(ca, domain, repository, package))
    markers = {v: f"sim2real::{package}::{v}" for v in _VERSIONS}

    for version in _VERSIONS:
        srcdir = os.path.join(workdir, f"src-{version}")
        _write_fixture(srcdir, package, version, markers[version])
        published = _npm(["publish"], cwd=srcdir, env=env, npmrc=npmrc)
        assert published.returncode == 0, (
            f"`npm publish` for {package}@{version} exited {published.returncode}; stderr: "
            f"{published.stderr[-400:]!r}"
        )

    listed = _versions(ca, domain, repository, package)
    assert listed == set(_VERSIONS), (
        f"ListPackageVersions reports {sorted(listed)!r} after three npm publishes, expected "
        f"{sorted(_VERSIONS)!r}"
    )

    # npm, not this check, resolves the range from the packument the repository serves.
    consumer = os.path.join(workdir, "consumer")
    os.makedirs(consumer, exist_ok=True)
    with open(os.path.join(consumer, "package.json"), "w", encoding="utf-8") as fh:
        json.dump({"name": "sim2real-consumer", "version": "1.0.0", "private": True}, fh)
    installed = _npm(["install", f"{package}@{_RANGE}", "--no-audit", "--no-fund",
                      "--ignore-scripts"], cwd=consumer, env=env, npmrc=npmrc)
    assert installed.returncode == 0, (
        f"`npm install {package}@{_RANGE}` exited {installed.returncode}; stderr: "
        f"{installed.stderr[-600:]!r}. npm verifies dist.integrity on install, so a hash the "
        f"repository advertised that does not match the bytes it served fails here"
    )

    module_path = os.path.join(consumer, "node_modules", package, "index.js")
    assert os.path.isfile(module_path), (
        f"{module_path!r} does not exist after a successful install; npm reported success without "
        f"materialising the package"
    )
    with open(module_path, encoding="utf-8") as fh:
        on_disk = fh.read()
    assert markers[_EXPECTED] in on_disk, (
        f"the installed module contains {on_disk[:200]!r}; the range {_RANGE!r} must have resolved "
        f"to {_EXPECTED} (marker {markers[_EXPECTED]!r}), not to another published version"
    )
    for other, marker in markers.items():
        if other != _EXPECTED:
            assert marker not in on_disk, (
                f"the installed module carries {other}'s marker {marker!r}; the range {_RANGE!r} "
                f"resolved to the wrong version"
            )

    lock_path = os.path.join(consumer, "package-lock.json")
    assert os.path.isfile(lock_path), (
        f"{lock_path!r} does not exist; npm records the resolved version and its integrity there "
        f"and this check reads that record rather than trusting its own arithmetic"
    )
    with open(lock_path, encoding="utf-8") as fh:
        lock = json.load(fh)
    entry = _lock_entry(lock, package)
    assert entry["version"] == _EXPECTED, (
        f"npm's lockfile records version {entry['version']!r} for {package!r}; the range "
        f"{_RANGE!r} over published versions {sorted(_VERSIONS)!r} must resolve to {_EXPECTED!r}"
    )
    assert entry["resolved"].startswith(endpoint), (
        f"npm resolved the tarball from {entry['resolved']!r}, which is outside the repository "
        f"endpoint {endpoint!r} — the install must not have reached a public registry"
    )
    integrity = entry["integrity"]
    assert integrity.startswith("sha512-"), (
        f"npm recorded integrity {integrity!r}; npm's own default for a modern registry is sha512, "
        f"so a weaker algorithm means the repository advertised no sha512 subresource integrity"
    )

    # CodeArtifact names the npm tarball asset "package.tgz", not npm's <package>-<version>.tgz.
    listed_assets = _list_all_assets(ca, domain, repository, package, _EXPECTED)
    assert listed_assets == ["package.tgz"], (
        f"ListPackageVersionAssets reports {listed_assets!r} for {package}@{_EXPECTED}; expected "
        f"exactly one asset named 'package.tgz' -- CodeArtifact's fixed name for an npm tarball, "
        f"independent of the package name and version"
    )
    asset_name = "package.tgz"
    stored = ca.get_package_version_asset(
        domain=domain, repository=repository, format="npm", package=package,
        packageVersion=_EXPECTED, asset=asset_name)["asset"].read()
    recomputed = "sha512-" + base64.b64encode(hashlib.sha512(stored).digest()).decode()
    assert integrity == recomputed, (
        f"npm recorded integrity {integrity!r} but the {len(stored)} bytes "
        f"GetPackageVersionAsset returns for {asset_name!r} hash to {recomputed!r}; the repository "
        f"must advertise the digest of what it actually stores, or every npm install of it fails"
    )
    hashes = _asset_hashes(ca, domain, repository, package, _EXPECTED, asset_name)
    api_sha512 = base64.b64encode(binascii.unhexlify(hashes["SHA-512"])).decode()
    assert integrity == "sha512-" + api_sha512, (
        f"ListPackageVersionAssets reports SHA-512 {hashes['SHA-512']!r} (= sha512-{api_sha512}) "
        f"while npm recorded {integrity!r}; the control plane and the registry protocol must agree "
        f"on the digest of one artifact"
    )
    assert hashes["SHA-256"] == hashlib.sha256(stored).hexdigest(), (
        f"ListPackageVersionAssets reports SHA-256 {hashes['SHA-256']!r} for bytes that hash to "
        f"{hashlib.sha256(stored).hexdigest()!r}"
    )

    loaded = _run([shutil.which("node") or "node", "-p", f"require({json.dumps(package)})"],
                  cwd=consumer, env=env)
    assert loaded.returncode == 0, (
        f"`node -p require({package!r})` exited {loaded.returncode}; stderr: "
        f"{loaded.stderr[-400:]!r}. An installed package that cannot be loaded is unusable"
    )
    assert loaded.stdout.strip() == markers[_EXPECTED], (
        f"node printed {loaded.stdout.strip()!r} for the installed module, expected the "
        f"{_EXPECTED} marker {markers[_EXPECTED]!r}"
    )


def _write_npmrc(path: str, endpoint: str, token: str) -> None:
    """The npmrc CodeArtifact documents: a pinned registry plus a host-scoped auth token.

    The auth key is the endpoint minus its scheme, keeping its trailing slash."""
    host_and_path = endpoint.split("://", 1)[1]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"registry={endpoint}\n")
        fh.write(f"//{host_and_path}:_authToken={token}\n")
        fh.write(f"//{host_and_path}:always-auth=true\n")


def _npm_env(ctx, workdir: str, npmrc: str, endpoint: str) -> dict[str, str]:
    """An npm environment isolated from the host's npm state and pinned to the repository.

    HOME and the cache live in the temp dir; update-notifier is off so npm never reaches npmjs.org."""
    env = ctx.subprocess_env()
    env.update({
        "HOME": workdir,
        "npm_config_userconfig": npmrc,
        "npm_config_cache": os.path.join(workdir, "npm-cache"),
        "npm_config_registry": endpoint,
        "npm_config_update_notifier": "false",
        "npm_config_fund": "false",
        "npm_config_audit": "false",
        "NO_UPDATE_NOTIFIER": "1",
    })
    return env


def _write_fixture(srcdir: str, name: str, version: str, marker: str) -> None:
    """One publishable npm package whose only export is a version-identifying marker."""
    os.makedirs(srcdir, exist_ok=True)
    with open(os.path.join(srcdir, "package.json"), "w", encoding="utf-8") as fh:
        json.dump({"name": name, "version": version, "main": "index.js",
                   "description": "sim2real fidelity fixture", "license": "MIT"}, fh)
    with open(os.path.join(srcdir, "index.js"), "w", encoding="utf-8") as fh:
        fh.write(f"module.exports = {json.dumps(marker)};\n")


def _npm(args: list[str], *, cwd: str, env: dict[str, str], npmrc: str):
    """One npm invocation; userconfig is passed on the command line and in the env because npm
    versions differ in which they honour."""
    npm = shutil.which("npm") or "npm"
    return _run([npm, *args, f"--userconfig={npmrc}"], cwd=cwd, env=env)


def _run(argv: list[str], *, cwd: str, env: dict[str, str]):
    """A bounded subprocess; a timeout raises so a hung client is never mistaken for a refusal."""
    try:
        return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True,
                              timeout=_NPM_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"{argv[0]!r} did not finish within {_NPM_TIMEOUT_SECONDS}s: {' '.join(argv[1:])!r}"
        ) from exc


def _lock_entry(lock: dict, package: str) -> dict:
    """The installed package's lockfile record (lockfile v3 or v2); raise if it is absent."""
    v3 = lock.get("packages", {}).get(f"node_modules/{package}")
    if v3 is not None:
        return v3
    v2 = lock.get("dependencies", {}).get(package)
    if v2 is not None:
        return v2
    raise AssertionError(
        f"package-lock.json has no entry for {package!r}; lockfileVersion="
        f"{lock.get('lockfileVersion')!r}, packages keys={sorted(lock.get('packages', {}))!r}, "
        f"dependencies keys={sorted(lock.get('dependencies', {}))!r}"
    )


def _versions(ca, domain: str, repository: str, package: str) -> set[str]:
    """Every page of ListPackageVersions for one npm package."""
    out, next_token = set(), None
    while True:
        page = ca.list_package_versions(
            domain=domain, repository=repository, format="npm", package=package,
            **({"nextToken": next_token} if next_token else {}))
        out.update(v["version"] for v in page["versions"])
        next_token = page.get("nextToken")
        if not next_token:
            return out


def _list_all_assets(ca, domain: str, repository: str, package: str, version: str) -> list[str]:
    """Every asset name ListPackageVersionAssets reports for one package version, across pages."""
    out, next_token = [], None
    while True:
        page = ca.list_package_version_assets(
            domain=domain, repository=repository, format="npm", package=package,
            packageVersion=version, **({"nextToken": next_token} if next_token else {}))
        out.extend(entry["name"] for entry in page["assets"])
        next_token = page.get("nextToken")
        if not next_token:
            return out


def _asset_hashes(ca, domain: str, repository: str, package: str, version: str,
                  asset: str) -> dict[str, str]:
    """The `hashes` map for one named asset, across every page."""
    next_token = None
    while True:
        page = ca.list_package_version_assets(
            domain=domain, repository=repository, format="npm", package=package,
            packageVersion=version, **({"nextToken": next_token} if next_token else {}))
        for entry in page["assets"]:
            if entry["name"] == asset:
                return entry["hashes"]
        next_token = page.get("nextToken")
        if not next_token:
            raise AssertionError(
                f"ListPackageVersionAssets never named {asset!r} for {package}@{version}"
            )


def _delete_package(ca, domain: str, repository: str, package: str) -> None:
    try:
        ca.delete_package(domain=domain, repository=repository, format="npm", package=package)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_repository(ca, domain: str, repository: str, timeout_s: float = 120.0) -> None:
    """DeleteRepository, retrying while the service still sees a dependent reference."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_repository(domain=domain, repository=repository)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _delete_domain(ca, domain: str, timeout_s: float = 120.0) -> None:
    """DeleteDomain, retrying while the service still sees a repository in the domain."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
