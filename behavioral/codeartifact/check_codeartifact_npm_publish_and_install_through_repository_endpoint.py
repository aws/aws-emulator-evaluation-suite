"""codeartifact-npm-publish-and-install-through-repository-endpoint."""
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


CHECK = "codeartifact-npm-publish-and-install-through-repository-endpoint"
GROUP = 'package-endpoint'
SERVICES = ['codeartifact']


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A tarball published over the npm registry protocol appears in the packument as the only and
    latest version with the sha1 of what was published, downloads back byte-identically from the
    repository endpoint, and ListPackageVersions reports the same version."""
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

    package = ctx.unique_name("sim2real-npm-")
    payload = b"sim2real npm payload: the exact bytes the endpoint must serve back\n"
    tarball = _npm_tarball(package, "1.0.0", payload)

    put_status, put_body = _http(ctx, endpoint + urllib.parse.quote(package, safe=""), method="PUT",
                                 token=token, content_type="application/json",
                                 body=_npm_publish_envelope(package, "1.0.0", tarball))
    assert put_status == 200, f"npm publish returned {put_status!r}: {put_body[:400]!r}"

    pm_status, pm_body = _http(ctx, endpoint + urllib.parse.quote(package, safe=""), token=token)
    assert pm_status == 200, f"packument GET returned {pm_status!r}: {pm_body[:400]!r}"
    packument = json.loads(pm_body)
    assert set(packument["versions"]) == {"1.0.0"}, (
        f"packument versions were {sorted(packument['versions'])!r}, expected exactly ['1.0.0']"
    )
    assert packument["dist-tags"]["latest"] == "1.0.0", (
        f"latest resolved to {packument['dist-tags']['latest']!r}, expected '1.0.0'"
    )

    dist = packument["versions"]["1.0.0"]["dist"]
    assert dist["tarball"].startswith(endpoint), (
        f"the tarball URL escaped the repository endpoint {endpoint!r}: {dist['tarball']!r}"
    )
    assert dist["shasum"] == hashlib.sha1(tarball).hexdigest(), (
        f"advertised shasum {dist['shasum']!r} is not sha1 of the published tarball "
        f"{hashlib.sha1(tarball).hexdigest()!r}"
    )

    tgz_status, fetched = _http(ctx, dist["tarball"], token=token)
    assert tgz_status == 200, f"tarball GET returned {tgz_status!r}: {fetched[:400]!r}"
    assert fetched == tarball, (
        f"the endpoint served {len(fetched)!r} bytes (sha1 "
        f"{hashlib.sha1(fetched).hexdigest()!r}) for a {len(tarball)!r}-byte publish (sha1 "
        f"{hashlib.sha1(tarball).hexdigest()!r})"
    )
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(fetched))) as tar:
        served_payload = tar.extractfile("package/index.js").read()
    assert served_payload == payload, (
        f"the file inside the served tarball is {served_payload!r}, published {payload!r}"
    )

    api_versions = {v["version"] for v in _list_package_versions(
        ca, domain=domain, repository=repository, format="npm", package=package)}
    assert api_versions == {"1.0.0"}, (
        f"ListPackageVersions reported {sorted(api_versions)!r}, but the endpoint served "
        f"{sorted(packument['versions'])!r}"
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
    """The PUT body `npm publish` sends: manifest + dist-tags + base64 tarball attachment.

    libnpmpublish keys the attachment by the FULL package name, scope included.
    """
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


def _list_package_versions(ca, **kwargs) -> list[dict]:
    """Every page of ListPackageVersions."""
    out, next_token = [], None
    while True:
        page = ca.list_package_versions(**kwargs,
                                        **({"nextToken": next_token} if next_token else {}))
        out.extend(page.get("versions", []))
        next_token = page.get("nextToken")
        if not next_token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
