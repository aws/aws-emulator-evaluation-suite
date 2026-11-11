"""codeartifact-archived-version-tarball-download-rejected-while-published-sibling-serves."""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
import urllib.error
import urllib.parse
import urllib.request

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "codeartifact-archived-version-tarball-download-rejected-while-published-sibling-serves"
GROUP = 'package-status'
SERVICES = ['codeartifact']


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Archiving a version makes the npm endpoint refuse its tarball with HTTP 400 naming the status,
    while its asset metadata survives, the Published sibling still serves, and restoring re-serves.
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
    package = ctx.unique_name("sim2real-archive-")
    marker = b"sim2real-archived-content-marker"
    tarballs = {v: _npm_tarball(package, v, marker + f"-{v}\n".encode())
                for v in ("1.0.0", "2.0.0")}
    for version, tarball in tarballs.items():
        status, body = _http(ctx, endpoint + urllib.parse.quote(package, safe=""), method="PUT",
                             token=token, content_type="application/json",
                             body=_npm_publish_envelope(package, version, tarball))
        assert status == 200, f"publishing {version!r} returned {status!r}: {body[:300]!r}"

    pm_status, pm_body = _http(ctx, endpoint + urllib.parse.quote(package, safe=""), token=token)
    assert pm_status == 200, f"packument GET returned {pm_status!r}: {pm_body[:300]!r}"
    packument = json.loads(pm_body)
    urls = {v: packument["versions"][v]["dist"]["tarball"] for v in ("1.0.0", "2.0.0")}

    # Barrier: both downloads work first, so a refusal cannot mean the publish had not landed.
    for version, url in urls.items():
        status, served = _http(ctx, url, token=token)
        assert status == 200 and served == tarballs[version], (
            f"the download path was not working before the status change: {version!r} returned "
            f"{status!r} / {len(served)!r} bytes, expected 200 / {len(tarballs[version])!r}"
        )

    result = ca.update_package_versions_status(
        domain=domain, repository=repository, format="npm", package=package,
        versions=["2.0.0"], targetStatus="Archived")
    assert result["successfulVersions"]["2.0.0"]["status"] == "Archived", (
        f"UpdatePackageVersionsStatus reported {result['successfulVersions']!r} / "
        f"failed {result.get('failedVersions')!r}"
    )

    refused_status, refused_body = _http(ctx, urls["2.0.0"], token=token)
    assert refused_status == 400, (
        f"expected HTTP 400 from the endpoint for an Archived version's tarball, got "
        f"{refused_status!r}: {refused_body[:300]!r}"
    )
    assert "Archived" in refused_body.decode(errors="replace"), (
        f"the refusal did not name the version status as the reason: {refused_body[:300]!r}"
    )
    # Effect absent: no part of the archived artifact came back with the refusal.
    assert marker not in refused_body and refused_body[:2] != b"\x1f\x8b", (
        f"the refusal leaked the archived tarball: {refused_body[:200]!r}"
    )

    # The bytes were refused, not deleted: the control plane still describes the asset.
    described = ca.describe_package_version(
        domain=domain, repository=repository, format="npm", package=package,
        packageVersion="2.0.0")["packageVersion"]
    assert described["status"] == "Archived", (
        f"DescribePackageVersion reported status {described['status']!r} after archiving"
    )
    assets = _paginate(ca.list_package_version_assets, "assets", domain=domain,
                      repository=repository, format="npm", package=package,
                      packageVersion="2.0.0")
    assert [a["hashes"]["SHA-256"] for a in assets] == [
        hashlib.sha256(tarballs["2.0.0"]).hexdigest()], (
        f"the archived version's asset metadata changed: {assets!r}"
    )

    # Positive control, same file, same repository: the Published sibling still serves.
    control_status, control_bytes = _http(ctx, urls["1.0.0"], token=token)
    assert control_status == 200, (
        f"the Published sibling's tarball broke too: {control_status!r} "
        f"{control_bytes[:300]!r}"
    )
    assert control_bytes == tarballs["1.0.0"], (
        f"the Published sibling served {len(control_bytes)!r} bytes (sha1 "
        f"{hashlib.sha1(control_bytes).hexdigest()!r}), published {len(tarballs['1.0.0'])!r} "
        f"(sha1 {hashlib.sha1(tarballs['1.0.0']).hexdigest()!r})"
    )
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(control_bytes))) as tar:
        assert tar.extractfile("package/index.js").read() == marker + b"-1.0.0\n", (
            "the Published sibling's payload changed as a side effect of archiving 2.0.0"
        )

    # Restore: Archived is a relabel, not a terminal state (unlike Disposed), so the identical
    # download that was just refused must succeed again once 2.0.0 is moved back to Published.
    restore = ca.update_package_versions_status(
        domain=domain, repository=repository, format="npm", package=package,
        versions=["2.0.0"], targetStatus="Published")
    assert restore["successfulVersions"]["2.0.0"]["status"] == "Published", (
        f"restoring 2.0.0 to Published reported {restore['successfulVersions']!r} / "
        f"failed {restore.get('failedVersions')!r}"
    )
    restored_status, restored_body = _http(ctx, urls["2.0.0"], token=token)
    assert restored_status == 200, (
        f"the identical download refused while Archived still failed after restoring to "
        f"Published: {restored_status!r} {restored_body[:300]!r}"
    )
    assert restored_body == tarballs["2.0.0"], (
        f"the restored version served {len(restored_body)!r} bytes (sha1 "
        f"{hashlib.sha1(restored_body).hexdigest()!r}), published {len(tarballs['2.0.0'])!r} "
        f"(sha1 {hashlib.sha1(tarballs['2.0.0']).hexdigest()!r})"
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


def _paginate(operation, key: str, **kwargs) -> list[dict]:
    """Every page of a CodeArtifact List* call."""
    out, next_token = [], None
    while True:
        page = operation(**kwargs, **({"nextToken": next_token} if next_token else {}))
        out.extend(page.get(key, []))
        next_token = page.get("nextToken")
        if not next_token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
