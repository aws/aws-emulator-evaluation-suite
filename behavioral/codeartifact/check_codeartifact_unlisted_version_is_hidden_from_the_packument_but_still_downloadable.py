"""codeartifact-unlisted-version-is-hidden-from-the-packument-but-still-downloadable."""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "codeartifact-unlisted-version-is-hidden-from-the-packument-but-still-downloadable"
GROUP = 'package-status'
SERVICES = ['codeartifact']


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Unlisting the latest version withdraws it from the packument and empties `dist-tags`,
    defaultDisplayVersion falls back to 1.0.0, and its pinned tarball URL still serves the bytes.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    token = ca.get_authorization_token(domain=domain,
                                       durationSeconds=900)["authorizationToken"]
    endpoint = ca.get_repository_endpoint(domain=domain, repository=repository,
                                          format="npm")["repositoryEndpoint"]
    package = ctx.unique_name("sim2real-unlist-")
    tarballs = {v: _npm_tarball(package, v, f"sim2real payload for {v}\n".encode())
                for v in ("1.0.0", "2.0.0")}
    for version, tarball in tarballs.items():
        status, body = _http(ctx, endpoint + urllib.parse.quote(package, safe=""), method="PUT",
                             token=token, content_type="application/json",
                             body=_npm_publish_envelope(package, version, tarball))
        assert status == 200, f"publishing {version!r} returned {status!r}: {body[:300]!r}"

    before = _packument(ctx, endpoint, package, token)
    assert set(before["versions"]) == {"1.0.0", "2.0.0"}, (
        f"the packument started as {sorted(before['versions'])!r}, expected both versions"
    )
    assert before["dist-tags"] == {"latest": "2.0.0"}, (
        f"dist-tags started as {before['dist-tags']!r}, expected latest to be 2.0.0"
    )
    urls = {v: before["versions"][v]["dist"]["tarball"] for v in ("1.0.0", "2.0.0")}

    result = ca.update_package_versions_status(
        domain=domain, repository=repository, format="npm", package=package,
        versions=["2.0.0"], targetStatus="Unlisted")
    assert result["successfulVersions"]["2.0.0"]["status"] == "Unlisted", (
        f"UpdatePackageVersionsStatus reported {result['successfulVersions']!r} / "
        f"failed {result.get('failedVersions')!r}"
    )

    after = _poll(lambda: _packument(ctx, endpoint, package, token),
                  lambda pm: "2.0.0" not in pm["versions"], timeout_s=90.0, interval_s=3.0)
    assert set(after["versions"]) == {"1.0.0"}, (
        f"the packument still advertises {sorted(after['versions'])!r} after 2.0.0 was unlisted"
    )
    assert after["dist-tags"] == {}, (
        f"dist-tags after unlisting the latest version are {after['dist-tags']!r}; real "
        f"CodeArtifact empties them rather than re-pointing latest at 1.0.0"
    )

    # The unlisted version stays downloadable at the URL the packument used to advertise:
    # that is precisely what distinguishes Unlisted from Archived.
    unlisted_status, unlisted_bytes = _http(ctx, urls["2.0.0"], token=token)
    assert unlisted_status == 200, (
        f"the unlisted version's tarball returned {unlisted_status!r}: {unlisted_bytes[:300]!r} — "
        f"Unlisted must hide the version from discovery, not withdraw its bytes"
    )
    assert unlisted_bytes == tarballs["2.0.0"], (
        f"the unlisted tarball served {len(unlisted_bytes)!r} bytes (sha1 "
        f"{hashlib.sha1(unlisted_bytes).hexdigest()!r}) for a {len(tarballs['2.0.0'])!r}-byte "
        f"publish (sha1 {hashlib.sha1(tarballs['2.0.0']).hexdigest()!r})"
    )

    published_status, published_bytes = _http(ctx, urls["1.0.0"], token=token)
    assert published_status == 200, (
        f"the surviving Published version's tarball returned {published_status!r}: "
        f"{published_bytes[:300]!r}"
    )
    assert published_bytes == tarballs["1.0.0"], (
        f"the surviving version served {len(published_bytes)!r} bytes, published "
        f"{len(tarballs['1.0.0'])!r}"
    )

    listing = ca.list_package_versions(domain=domain, repository=repository, format="npm",
                                       package=package)
    assert {v["version"]: v["status"] for v in listing["versions"]} == {
        "1.0.0": "Published", "2.0.0": "Unlisted"}, (
        f"the control plane reports {[(v['version'], v['status']) for v in listing['versions']]!r}"
    )
    assert listing["defaultDisplayVersion"] == "1.0.0", (
        f"defaultDisplayVersion is {listing['defaultDisplayVersion']!r} after unlisting 2.0.0, "
        f"expected the fallback to 1.0.0"
    )


def _http(ctx, url: str, *, method: str = "GET", token: str | None = None, body: bytes | None = None,
          content_type: str | None = None, timeout_s: float = 60.0) -> tuple[int, bytes]:
    """One package-manager-protocol exchange, returning (status, body) for any HTTP status."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if content_type:
        headers["Content-Type"] = content_type
    req = _routed_request(ctx, url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _packument(ctx, endpoint: str, package: str, token: str) -> dict:
    """The npm packument the endpoint currently serves, asserted to be readable."""
    status, body = _http(ctx, endpoint + urllib.parse.quote(package, safe=""), token=token)
    assert status == 200, f"packument GET returned {status!r}: {body[:300]!r}"
    return json.loads(body)


def _npm_tarball(name: str, version: str, payload: bytes) -> bytes:
    """A deterministic npm tarball: gzipped tar with everything under `package/`."""
    manifest = json.dumps({"name": name, "version": version, "main": "index.js",
                           "description": "sim2real fidelity fixture", "license": "MIT"},
                          sort_keys=True, separators=(",", ":")).encode()
    buf = io.BytesIO()
    gz = gzip.GzipFile(fileobj=buf, mode="wb", mtime=0)
    with tarfile.open(fileobj=gz, mode="w") as tar:
        for member, data in (("package/package.json", manifest), ("package/index.js", payload)):
            info = tarfile.TarInfo(member)
            info.size, info.mtime, info.mode, info.uid, info.gid = len(data), 0, 0o644, 0, 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    gz.close()
    return buf.getvalue()


def _npm_publish_envelope(name: str, version: str, tarball: bytes) -> bytes:
    """The PUT body `npm publish` sends; libnpmpublish keys the attachment by the full name."""
    attachment = f"{name}-{version}.tgz"
    return json.dumps({
        "_id": name, "name": name, "description": "sim2real fidelity fixture",
        "dist-tags": {"latest": version},
        "versions": {version: {
            "name": name, "version": version, "_id": f"{name}@{version}",
            "description": "sim2real fidelity fixture", "main": "index.js", "license": "MIT",
            "dist": {
                "shasum": hashlib.sha1(tarball).hexdigest(),
                "integrity": "sha512-" + base64.b64encode(
                    hashlib.sha512(tarball).digest()).decode(),
                "tarball": f"http://localhost/{name}/-/{attachment}",
            },
        }},
        "access": "public",
        "_attachments": {attachment: {"content_type": "application/octet-stream",
                                      "data": base64.b64encode(tarball).decode(),
                                      "length": len(tarball)}},
    }).encode()


def _poll(read, predicate, *, timeout_s: float, interval_s: float):
    """Bounded poll on an observable condition; returns the last read either way."""
    deadline = time.monotonic() + timeout_s
    while True:
        observed = read()
        if predicate(observed) or time.monotonic() >= deadline:
            return observed
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
