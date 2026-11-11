"""package-version-details-are-extracted-from-the-manifest-and-latest-decides-the-display-version."""

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


CHECK = (
    "package-version-details-are-extracted-from-the-manifest-and-latest-decides-the-display-version"
)
GROUP = "package-endpoint"
SERVICES = ["codeartifact"]

_DESCRIPTION = "sim2real: a summary CodeArtifact must lift out of package.json"
_HOMEPAGE = "https://example.invalid/sim2real/codeartifact-metadata"
_LICENSE = "Apache-2.0"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """CodeArtifact derives summary/homePage/licenses/displayName from the published package.json,
    and defaultDisplayVersion follows the npm `latest` dist-tag even when it points at an older
    version.

    Reference: https://docs.aws.amazon.com/codeartifact/latest/ug/describe-package-version.html
    """
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
    endpoint = ca.get_repository_endpoint(domain=domain, repository=repository,
                                          format="npm")["repositoryEndpoint"]

    plain = ctx.unique_name("sim2real-meta-")
    ctx.on_cleanup(lambda: _delete_package(ca, domain, repository, plain))

    # ---- publish 1.0.0 then 2.0.0, in that order --------------------------------------------
    for version in ("1.0.0", "2.0.0"):
        tarball = _npm_tarball(plain, version, f"module.exports={version!r};\n".encode(),
                               description=_DESCRIPTION, homepage=_HOMEPAGE, license_=_LICENSE)
        status, body = _http(ctx, endpoint + urllib.parse.quote(plain, safe=""), method="PUT",
                             token=token, content_type="application/json",
                             body=_npm_publish_envelope(plain, version, tarball,
                                                        description=_DESCRIPTION,
                                                        homepage=_HOMEPAGE, license_=_LICENSE))
        assert status == 200, f"publishing {plain}@{version} returned {status!r}: {body[:300]!r}"

    # ---- the details the service lifted out of package.json ----------------------------------
    described = ca.describe_package_version(
        domain=domain, repository=repository, format="npm", package=plain,
        packageVersion="2.0.0")["packageVersion"]
    assert described["summary"] == _DESCRIPTION, (
        f"summary is {described.get('summary')!r}; CodeArtifact must extract it from the tarball's "
        f"package.json 'description', which was {_DESCRIPTION!r}"
    )
    assert described["homePage"] == _HOMEPAGE, (
        f"homePage is {described.get('homePage')!r}; the published package.json declared homepage "
        f"{_HOMEPAGE!r}"
    )
    licenses = described["licenses"]
    assert len(licenses) == 1, (
        f"licenses is {licenses!r}; the manifest declared exactly one license string "
        f"({_LICENSE!r}), so exactly one entry must come back"
    )
    assert licenses[0]["name"] == _LICENSE, (
        f"licenses[0] is {licenses[0]!r}; the manifest declared license {_LICENSE!r} and "
        f"LicenseInfo.name is where the model puts a license name"
    )
    assert described["displayName"] == plain, (
        f"displayName is {described['displayName']!r} for an unscoped npm package named {plain!r}; "
        f"an unscoped package's display name is its name"
    )
    assert "namespace" not in described or described["namespace"] in (None, ""), (
        f"an unscoped npm package reports namespace {described.get('namespace')!r}, expected none"
    )

    # The two versions' publishedTime respect the order they were published in.
    first_time = ca.describe_package_version(
        domain=domain, repository=repository, format="npm", package=plain,
        packageVersion="1.0.0")["packageVersion"]["publishedTime"]
    assert described["publishedTime"] >= first_time, (
        f"2.0.0's publishedTime {described['publishedTime']!r} precedes 1.0.0's {first_time!r}, "
        f"but 1.0.0 was published first"
    )

    # ---- latest points at the newest, so both candidate rules agree: the baseline ----------
    baseline = ca.list_package_versions(domain=domain, repository=repository, format="npm",
                                        package=plain)
    assert baseline["defaultDisplayVersion"] == "2.0.0", (
        f"defaultDisplayVersion is {baseline['defaultDisplayVersion']!r} while latest points at "
        f"2.0.0; expected 2.0.0 before the tag is moved"
    )

    # ---- repoint `latest` BACKWARDS, which separates the two candidate rules ----------------
    tag_url = (endpoint + "-/package/" + urllib.parse.quote(plain, safe="")
               + "/dist-tags/latest")
    tag_status, tag_body = _http(ctx, tag_url, method="PUT", token=token,
                                 content_type="application/json", body=json.dumps("1.0.0").encode())
    assert 200 <= tag_status < 300, (
        f"the npm dist-tag route {tag_url!r} returned {tag_status!r}: {tag_body[:300]!r}. This is "
        f"the request `npm dist-tag add {plain}@1.0.0 latest` issues; without it the rest of this "
        f"check cannot separate 'the latest tag' from 'the most recent publish'"
    )
    # Independent read at the endpoint: the tag really moved, so the assertion below is not vacuous.
    pm_status, pm_body = _http(ctx, endpoint + urllib.parse.quote(plain, safe=""), token=token)
    assert pm_status == 200, f"the packument GET returned {pm_status!r}: {pm_body[:300]!r}"
    packument = json.loads(pm_body)
    assert packument["dist-tags"]["latest"] == "1.0.0", (
        f"the packument reports dist-tags {packument['dist-tags']!r} after repointing latest at "
        f"1.0.0; the tag move must be observable before defaultDisplayVersion is judged"
    )
    assert set(packument["versions"]) == {"1.0.0", "2.0.0"}, (
        f"the packument lists {sorted(packument['versions'])!r}; moving a tag must not withdraw a "
        f"version"
    )

    moved = _poll(
        lambda: ca.list_package_versions(domain=domain, repository=repository, format="npm",
                                         package=plain)["defaultDisplayVersion"],
        lambda v: v == "1.0.0", timeout_s=120.0, interval_s=3.0,
        reason="defaultDisplayVersion to follow the repointed `latest` dist-tag to 1.0.0")
    assert moved == "1.0.0", (
        f"defaultDisplayVersion is {moved!r} after `latest` was repointed at 1.0.0. 2.0.0 is still "
        f"Published, still the highest semver, and still the most recently published — so a target "
        f"answering 2.0.0 here has implemented 'most recent publish' instead of the documented "
        f"'the version referenced by the latest tag'"
    )
    # And 2.0.0 is genuinely still there and still Published: the display version moved, nothing
    # else did.
    statuses = {v["version"]: v["status"] for v in ca.list_package_versions(
        domain=domain, repository=repository, format="npm", package=plain)["versions"]}
    assert statuses == {"1.0.0": "Published", "2.0.0": "Published"}, (
        f"the control plane reports {statuses!r}; moving a dist-tag changes no version's status"
    )

    # ---- a scoped package's displayName is derived, not echoed -----------------------------
    scope = ctx.unique_name("sim2rscope")
    scoped = ctx.unique_name("sim2real-scoped-")
    full = f"@{scope}/{scoped}"
    ctx.on_cleanup(lambda: _delete_package(ca, domain, repository, scoped, namespace=scope))
    scoped_tarball = _npm_tarball(full, "1.0.0", b"module.exports='scoped';\n",
                                  description=_DESCRIPTION, homepage=_HOMEPAGE, license_=_LICENSE)
    scoped_status, scoped_body = _http(ctx,
        endpoint + urllib.parse.quote(full, safe=""), method="PUT", token=token,
        content_type="application/json",
        body=_npm_publish_envelope(full, "1.0.0", scoped_tarball, description=_DESCRIPTION,
                                   homepage=_HOMEPAGE, license_=_LICENSE))
    assert scoped_status == 200, (
        f"publishing the scoped package {full!r} returned {scoped_status!r}: {scoped_body[:300]!r}"
    )
    scoped_described = ca.describe_package_version(
        domain=domain, repository=repository, format="npm", namespace=scope, package=scoped,
        packageVersion="1.0.0")["packageVersion"]
    assert (scoped_described["namespace"], scoped_described["packageName"]) == (scope, scoped), (
        f"the scoped publish landed as namespace/package "
        f"{(scoped_described.get('namespace'), scoped_described.get('packageName'))!r}, expected "
        f"{(scope, scoped)!r} — the '@' is not part of the namespace"
    )
    assert scoped_described["displayName"] == full, (
        f"displayName is {scoped_described['displayName']!r} for namespace {scope!r} and package "
        f"{scoped!r}; the documented derivation reassembles it as {full!r}"
    )


def _poll(read, predicate, *, timeout_s: float, interval_s: float, reason: str):
    """Bounded retry on an observable condition. RAISES on timeout, naming what it waited for."""
    deadline = time.monotonic() + timeout_s
    while True:
        observed = read()
        if predicate(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {reason}; last observation was {observed!r}"
            )
        time.sleep(interval_s)


def _http(ctx, url: str, *, method: str = "GET", token: str | None = None, body: bytes | None = None,
          content_type: str | None = None, timeout_s: float = 60.0) -> tuple[int, bytes]:
    """One npm-registry-protocol exchange, returning (status, body) for any HTTP status."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if content_type:
        headers["Content-Type"] = content_type
    req = _routed_request(ctx, url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _manifest(name: str, version: str, *, description: str, homepage: str,
              license_: str) -> dict[str, str]:
    """The package.json CodeArtifact is expected to PARSE, not merely store."""
    return {"name": name, "version": version, "main": "index.js", "description": description,
            "homepage": homepage, "license": license_}


def _npm_tarball(name: str, version: str, payload: bytes, *, description: str, homepage: str,
                 license_: str) -> bytes:
    """A deterministic npm tarball whose package.json carries the metadata under test."""
    manifest = json.dumps(_manifest(name, version, description=description, homepage=homepage,
                                    license_=license_),
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


def _npm_publish_envelope(name: str, version: str, tarball: bytes, *, description: str,
                          homepage: str, license_: str) -> bytes:
    """The PUT body `npm publish` sends; the attachment is keyed by the full name, verbatim,
    including any '@' and '/'."""
    attachment = f"{name}-{version}.tgz"
    version_doc = dict(_manifest(name, version, description=description, homepage=homepage,
                                 license_=license_))
    version_doc["_id"] = f"{name}@{version}"
    version_doc["dist"] = {
        "shasum": hashlib.sha1(tarball).hexdigest(),
        "integrity": "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode(),
        "tarball": f"http://localhost/{name}/-/{attachment}",
    }
    return json.dumps({
        "_id": name, "name": name, "description": description,
        "dist-tags": {"latest": version},
        "versions": {version: version_doc},
        "access": "public",
        "_attachments": {attachment: {"content_type": "application/octet-stream",
                                      "data": base64.b64encode(tarball).decode(),
                                      "length": len(tarball)}},
    }).encode()


def _delete_package(ca, domain: str, repository: str, package: str,
                    namespace: str | None = None) -> None:
    kwargs = {"namespace": namespace} if namespace else {}
    try:
        ca.delete_package(domain=domain, repository=repository, format="npm", package=package,
                          **kwargs)
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
