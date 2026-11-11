"""codeartifact-repository-policy-denying-read-blocks-the-endpoint-and-a-sibling-still-serves."""
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

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "codeartifact-repository-policy-denying-read-blocks-the-endpoint-and-a-sibling-still-serves"
GROUP = 'overly-permissive'
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
    """A repository-policy Deny on ReadFromRepository makes the npm endpoint answer 403, while the
    GetPackageVersionAsset API still reads the bytes, a sibling repository still serves, and
    deleting the policy restores the endpoint.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    denied = ctx.unique_name("sim2real-denied-")
    control = ctx.unique_name("sim2real-control-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": "policy-deny-endpoint"}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    endpoints = {}
    for repository in (denied, control):
        ca.create_repository(domain=domain, repository=repository,
                             tags=[{"key": "sim2real", "value": "policy-deny-endpoint"}])
        ctx.on_cleanup(lambda r=repository: ca.delete_repository(domain=domain, repository=r))
        endpoints[repository] = ca.get_repository_endpoint(
            domain=domain, repository=repository, format="npm")["repositoryEndpoint"]

    token = ca.get_authorization_token(domain=domain,
                                       durationSeconds=900)["authorizationToken"]
    package = ctx.unique_name("sim2real-policy-")
    marker = b"sim2real-repository-content-marker"
    tarball = _npm_tarball(package, "1.0.0", marker + b"\n")

    # Barrier: BOTH repositories must serve the identical package before anything is denied, so
    # a later refusal cannot be a publish that had not landed.
    urls = {}
    for repository, endpoint in endpoints.items():
        put_status, put_body = _http(ctx, endpoint + urllib.parse.quote(package, safe=""),
                                     method="PUT", token=token,
                                     content_type="application/json",
                                     body=_npm_publish_envelope(package, "1.0.0", tarball))
        assert put_status == 200, (
            f"publishing into {repository!r} returned {put_status!r}: {put_body[:300]!r}"
        )
        pm_status, pm_body = _http(ctx, endpoint + urllib.parse.quote(package, safe=""), token=token)
        assert pm_status == 200, (
            f"{repository!r}'s packument returned {pm_status!r} before any policy: "
            f"{pm_body[:300]!r}"
        )
        urls[repository] = json.loads(pm_body)["versions"]["1.0.0"]["dist"]["tarball"]
        tgz_status, served = _http(ctx, urls[repository], token=token)
        assert tgz_status == 200 and served == tarball, (
            f"{repository!r} was not serving correctly before the policy: {tgz_status!r} / "
            f"{len(served)!r} bytes, expected 200 / {len(tarball)!r}"
        )

    caller = ctx.client("sts").get_caller_identity()["Arn"]
    document = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Sid": "DenyReadFromRepository", "Effect": "Deny", "Principal": {"AWS": caller},
        "Action": "codeartifact:ReadFromRepository", "Resource": "*"}]})
    put = ca.put_repository_permissions_policy(domain=domain, repository=denied,
                                              policyDocument=document)
    ctx.on_cleanup(lambda: _drop_repository_policy(ca, domain, denied))
    assert put["policy"]["revision"], f"PutRepositoryPermissionsPolicy returned {put!r}"

    denied_status, denied_body = _http(ctx, endpoints[denied] + urllib.parse.quote(package, safe=""),
                                       token=token)
    assert denied_status == 403, (
        f"expected HTTP 403 from the endpoint after an explicit Deny on ReadFromRepository, got "
        f"{denied_status!r}: {denied_body[:300]!r}"
    )
    assert "codeartifact:ReadFromRepository" in denied_body.decode(errors="replace"), (
        f"the refusal did not name the denied action: {denied_body[:300]!r}"
    )
    # Effect absent: neither the packument nor the content came back with the refusal.
    assert marker not in denied_body and b"dist-tags" not in denied_body, (
        f"the denial response leaked repository content: {denied_body[:300]!r}"
    )
    tgz_status, tgz_body = _http(ctx, urls[denied], token=token)
    assert tgz_status == 403, (
        f"the tarball URL of the denied repository returned {tgz_status!r}, expected 403: "
        f"{tgz_body[:200]!r}"
    )
    assert tgz_body[:2] != b"\x1f\x8b" and marker not in tgz_body, (
        f"the denied tarball request leaked the artifact: {tgz_body[:200]!r}"
    )

    # The Deny is scoped to the endpoint action: the signed API still reads the same bytes.
    api_bytes = ca.get_package_version_asset(
        domain=domain, repository=denied, format="npm", package=package, packageVersion="1.0.0",
        asset="package.tgz")["asset"].read()
    assert api_bytes == tarball, (
        f"GetPackageVersionAsset returned {len(api_bytes)!r} bytes for a {len(tarball)!r}-byte "
        f"publish; the Deny was expected to bind ReadFromRepository only"
    )

    # Positive control, same domain, no policy: the sibling repository still serves.
    control_pm_status, control_pm_body = _http(ctx,
        endpoints[control] + urllib.parse.quote(package, safe=""), token=token)
    assert control_pm_status == 200, (
        f"the control repository's packument broke too: {control_pm_status!r} "
        f"{control_pm_body[:300]!r}"
    )
    control_status, control_bytes = _http(ctx, urls[control], token=token)
    assert control_status == 200, (
        f"the control repository's tarball returned {control_status!r}: {control_bytes[:200]!r}"
    )
    assert control_bytes == tarball, (
        f"the control repository served {len(control_bytes)!r} bytes (sha1 "
        f"{hashlib.sha1(control_bytes).hexdigest()!r}), published {len(tarball)!r} (sha1 "
        f"{hashlib.sha1(tarball).hexdigest()!r})"
    )
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(control_bytes))) as tar:
        assert tar.extractfile("package/index.js").read() == marker + b"\n", (
            "the control repository's payload changed as a side effect of denying its sibling"
        )

    stored = ca.get_repository_permissions_policy(domain=domain, repository=denied)["policy"]
    statement = json.loads(stored["document"])["Statement"][0]
    assert (statement["Effect"], statement["Action"]) == ("Deny",
                                                          "codeartifact:ReadFromRepository"), (
        f"the stored policy statement is {statement!r}, not the Deny that was written"
    )

    # Restore: deleting the Deny must let the identical call that was refused succeed again, so
    # the refusal above is attributable to the policy and not to some other break.
    ca.delete_repository_permissions_policy(domain=domain, repository=denied)
    restored_status, restored_body = _http(ctx,
        endpoints[denied] + urllib.parse.quote(package, safe=""), token=token)
    assert restored_status == 200, (
        f"deleting the Deny on ReadFromRepository must restore the identical packument request "
        f"that was refused above; got {restored_status!r}: {restored_body[:300]!r}"
    )
    restored_tgz_status, restored_tgz_body = _http(ctx, urls[denied], token=token)
    assert restored_tgz_status == 200 and restored_tgz_body == tarball, (
        f"deleting the Deny must restore the identical tarball request that was refused above; "
        f"got {restored_tgz_status!r} / {len(restored_tgz_body)!r} bytes, expected 200 / "
        f"{len(tarball)!r}"
    )


def _drop_repository_policy(ca, domain, repository):
    """Teardown-only: the body deletes the policy itself to prove restoration, so tolerate it
    already being gone."""
    try:
        ca.delete_repository_permissions_policy(domain=domain, repository=repository)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
