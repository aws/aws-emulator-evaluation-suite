"""codeartifact-scoped-npm-package-round-trips-under-its-url-encoded-namespace."""
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


CHECK = "codeartifact-scoped-npm-package-round-trips-under-its-url-encoded-namespace"
GROUP = 'package-endpoint'
SERVICES = ['codeartifact']


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """An @scope/name npm package published at `@scope%2Fname` serves its packument and tarball,
    lists as namespace=scope, package=name, and the unencoded path is rejected with HTTP 400.
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

    scope = ctx.unique_name("sim2real-scope-")
    scoped_name = f"@{scope}/pkg"
    encoded = urllib.parse.quote(scoped_name, safe="")
    assert encoded == f"%40{scope}%2Fpkg", (
        f"the fixture did not percent-encode the scoped name as npm does: {encoded!r}"
    )
    payload = b"sim2real scoped payload: the bytes behind @scope/pkg\n"
    tarball = _npm_tarball(scoped_name, "1.0.0", payload)

    put_status, put_body = _http(ctx, endpoint + encoded, method="PUT", token=token,
                                 content_type="application/json",
                                 body=_npm_publish_envelope(scoped_name, "1.0.0", tarball))
    assert put_status == 200, (
        f"publishing the scoped package to the encoded path returned {put_status!r}: "
        f"{put_body[:400]!r}"
    )

    enc_status, enc_body = _http(ctx, endpoint + encoded, token=token)
    assert enc_status == 200, (
        f"the encoded scoped path returned {enc_status!r}: {enc_body[:400]!r}"
    )
    packument = json.loads(enc_body)
    assert packument["name"] == scoped_name, (
        f"the packument name is {packument['name']!r}, expected the reassembled scoped name "
        f"{scoped_name!r}"
    )
    assert set(packument["versions"]) == {"1.0.0"}, (
        f"the scoped packument advertises {sorted(packument['versions'])!r}"
    )

    tarball_url = packument["versions"]["1.0.0"]["dist"]["tarball"]
    assert tarball_url.startswith(endpoint + scoped_name + "/-/"), (
        f"the advertised tarball URL does not put the scope slash back under the repository "
        f"endpoint: {tarball_url!r}"
    )
    tgz_status, served = _http(ctx, tarball_url, token=token)
    assert tgz_status == 200, f"the scoped tarball GET returned {tgz_status!r}: {served[:300]!r}"
    assert served == tarball, (
        f"the endpoint served {len(served)!r} bytes (sha1 "
        f"{hashlib.sha1(served).hexdigest()!r}) for a {len(tarball)!r}-byte publish (sha1 "
        f"{hashlib.sha1(tarball).hexdigest()!r})"
    )

    # The unencoded path is a DIFFERENT request: `@scope` alone is not a legal package name, and
    # CodeArtifact must say so rather than resolving it to anything.
    unencoded_status, unencoded_body = _http(ctx, endpoint + scoped_name, token=token)
    assert unencoded_status == 400, (
        f"the unencoded scoped path returned {unencoded_status!r}, expected 400: "
        f"{unencoded_body[:300]!r}"
    )
    assert f"'@{scope}'" in unencoded_body.decode(errors="replace"), (
        f"the rejection did not name the truncated scope as the invalid package: "
        f"{unencoded_body[:300]!r}"
    )

    packages = _paginate(ca.list_packages, "packages", domain=domain, repository=repository,
                        format="npm")
    assert [(p.get("namespace"), p["package"]) for p in packages] == [(scope, "pkg")], (
        f"ListPackages reported {packages!r}, expected the scope to become the namespace and "
        f"'pkg' the package"
    )
    described = ca.describe_package_version(
        domain=domain, repository=repository, format="npm", namespace=scope, package="pkg",
        packageVersion="1.0.0")["packageVersion"]
    assert described["status"] == "Published", (
        f"DescribePackageVersion under the split (namespace={scope!r}, package='pkg') reported "
        f"{described['status']!r}"
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
