"""codeartifact-upstream-chain-resolves-through-two-hops-and-caches-in-the-front-repository."""
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

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "codeartifact-upstream-chain-resolves-through-two-hops-and-caches-in-the-front-repository"
GROUP = 'upstreams'
SERVICES = ['codeartifact']


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """One npm packument GET on front repository A resolves a package held only by C via A -> B -> C,
    after which A, empty for that package before, holds a byte-identical copy whose origin names C.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    back = ctx.unique_name("sim2real-back-")
    mid = ctx.unique_name("sim2real-mid-")
    front = ctx.unique_name("sim2real-front-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    # Created back-to-front because an upstream must exist first; LIFO cleanup unwinds front -> mid
    # -> back, the only order the service permits. Deletes retry on ConflictException: releasing
    # an upstream reference is eventually consistent (refused, then accepted ~5 s later).
    ca.create_repository(domain=domain, repository=back,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, back))
    ca.create_repository(domain=domain, repository=mid, upstreams=[{"repositoryName": back}],
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, mid))
    ca.create_repository(domain=domain, repository=front, upstreams=[{"repositoryName": mid}],
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, front))

    token = ca.get_authorization_token(domain=domain,
                                       durationSeconds=900)["authorizationToken"]
    back_endpoint = ca.get_repository_endpoint(domain=domain, repository=back,
                                              format="npm")["repositoryEndpoint"]
    front_endpoint = ca.get_repository_endpoint(domain=domain, repository=front,
                                               format="npm")["repositoryEndpoint"]

    package = ctx.unique_name("sim2real-up-")
    payload = b"sim2real upstream payload: published into the BACK repository only\n"
    published = _npm_tarball(package, "1.0.0", payload)
    put_status, put_body = _http(ctx, back_endpoint + urllib.parse.quote(package, safe=""),
                                 method="PUT", token=token, content_type="application/json",
                                 body=_npm_publish_envelope(package, "1.0.0", published))
    assert put_status == 200, f"publish into the back repository returned {put_status!r}: {put_body[:400]!r}"

    pre = _rejection(lambda: ca.list_package_versions(
        domain=domain, repository=front, format="npm", package=package))
    expected_pre = ("ResourceNotFoundException",
                    f"The npm package '{package}' does not exist in repository '{front}'.")
    assert pre == expected_pre, (
        f"the front repository was expected to hold nothing for {package!r} before resolution, "
        f"but ListPackageVersions answered {pre!r}, expected {expected_pre!r}"
    )

    pm_status, pm_body = _http(ctx, front_endpoint + urllib.parse.quote(package, safe=""), token=token)
    assert pm_status == 200, (
        f"the front repository's endpoint returned {pm_status!r} for a package only the back "
        f"repository holds: {pm_body[:400]!r}"
    )
    tarball_url = json.loads(pm_body)["versions"]["1.0.0"]["dist"]["tarball"]
    assert tarball_url.startswith(front_endpoint), (
        f"the resolved tarball URL points outside the front repository {front_endpoint!r}: "
        f"{tarball_url!r}"
    )
    tgz_status, served = _http(ctx, tarball_url, token=token)
    assert tgz_status == 200, f"the resolved tarball GET returned {tgz_status!r}: {served[:300]!r}"
    assert served == published, (
        f"the front repository served {len(served)!r} bytes (sha1 "
        f"{hashlib.sha1(served).hexdigest()!r}) for a {len(published)!r}-byte publish (sha1 "
        f"{hashlib.sha1(published).hexdigest()!r})"
    )

    front_versions = _poll(
        lambda: {v["version"] for v in _list_package_versions(
            ca, domain=domain, repository=front, format="npm", package=package)},
        lambda vs: "1.0.0" in vs, timeout_s=120.0, interval_s=3.0, default=set())
    assert front_versions == {"1.0.0"}, (
        f"resolving through the chain did not materialise the version in the front repository: "
        f"ListPackageVersions reported {sorted(front_versions)!r}"
    )

    assets = _paginate(ca.list_package_version_assets, "assets", domain=domain, repository=front,
                      format="npm", package=package, packageVersion="1.0.0")
    assert len(assets) == 1, f"expected one cached asset in the front repository, got {assets!r}"
    cached = ca.get_package_version_asset(
        domain=domain, repository=front, format="npm", package=package, packageVersion="1.0.0",
        asset=assets[0]["name"])["asset"].read()
    assert cached == published, (
        f"the cached asset in the front repository is {len(cached)!r} bytes (sha1 "
        f"{hashlib.sha1(cached).hexdigest()!r}), the back repository published {len(published)!r} "
        f"(sha1 {hashlib.sha1(published).hexdigest()!r})"
    )

    origin = ca.describe_package_version(domain=domain, repository=front, format="npm",
                                         package=package,
                                         packageVersion="1.0.0")["packageVersion"]["origin"]
    assert origin["originType"] == "INTERNAL", (
        f"the resolved version's originType is {origin['originType']!r}, expected 'INTERNAL' for "
        f"a version reached through an in-domain upstream chain"
    )
    assert origin["domainEntryPoint"]["repositoryName"] == back, (
        f"origin names {origin['domainEntryPoint']['repositoryName']!r} as the entry point, "
        f"expected the back repository {back!r} two hops upstream"
    )


def _delete_repository(ca, domain: str, repository: str, timeout_s: float = 120.0) -> None:
    """DeleteRepository, retrying while the service still sees a downstream reference."""
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


def _rejection(fn) -> tuple[str, str]:
    """The (code, message) of a call that MUST be rejected; raises if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to be rejected but returned {result!r}")


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


def _list_package_versions(ca, **kwargs) -> list[dict]:
    """Every page of ListPackageVersions, tolerating the not-yet-materialised package."""
    out, next_token = [], None
    while True:
        try:
            page = ca.list_package_versions(**kwargs,
                                            **({"nextToken": next_token} if next_token else {}))
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return out
            raise
        out.extend(page.get("versions", []))
        next_token = page.get("nextToken")
        if not next_token:
            return out


def _paginate(operation, key: str, **kwargs) -> list[dict]:
    """Every page of a CodeArtifact List* call."""
    out, next_token = [], None
    while True:
        page = operation(**kwargs, **({"nextToken": next_token} if next_token else {}))
        out.extend(page.get(key, []))
        next_token = page.get("nextToken")
        if not next_token:
            return out


def _poll(read, predicate, *, timeout_s: float, interval_s: float, default):
    """Bounded poll on an observable condition; returns the last read either way."""
    deadline = time.monotonic() + timeout_s
    observed = default
    while True:
        observed = read()
        if predicate(observed) or time.monotonic() >= deadline:
            return observed
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
