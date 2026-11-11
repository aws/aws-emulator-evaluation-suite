"""ingested-package-defaults-to-publish-block-and-origin-type-partitions-the-versions."""

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


CHECK = "ingested-package-defaults-to-publish-block-and-origin-type-partitions-the-versions"
GROUP = "external-connections"
SERVICES = ["codeartifact"]



#: A public package that certainly exists on npmjs, and a version number that certainly does not.
_UPSTREAM_PACKAGE = "left-pad"
_UPSTREAM_VERSION = "1.3.0"
_PRIVATE_VERSION = "99.99.99"

#: How long ingestion may take to become visible to the control plane.
_INGEST_WAIT_SECONDS = 120.0


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """An ingested package defaults to publish=BLOCK, refusing a dependency-substitution publish
    until relaxed; ListPackageVersions originType then partitions versions by how each arrived.

    Reference: https://docs.aws.amazon.com/codeartifact/latest/ug/package-origin-controls.html
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-dom-")
    repository = ctx.unique_name("sim2real-ca-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, repository))
    ca.associate_external_connection(domain=domain, repository=repository,
                                     externalConnection="public:npmjs")
    ctx.on_cleanup(lambda: ca.disassociate_external_connection(
        domain=domain, repository=repository, externalConnection="public:npmjs"))
    ctx.on_cleanup(lambda: _delete_package(ca, domain, repository, _UPSTREAM_PACKAGE))

    token = ca.get_authorization_token(domain=domain,
                                       durationSeconds=43200)["authorizationToken"]
    endpoint = ca.get_repository_endpoint(domain=domain, repository=repository,
                                          format="npm")["repositoryEndpoint"]
    package_url = endpoint + urllib.parse.quote(_UPSTREAM_PACKAGE, safe="")

    # The repository knows nothing about this package yet, so the default that appears later can
    # only have come from the ingestion.
    absent = _rejection(lambda: ca.describe_package(
        domain=domain, repository=repository, format="npm", package=_UPSTREAM_PACKAGE))
    expected_absent = (
        "ResourceNotFoundException",
        f"Package not found in repository. Package = {{format=npm, name={_UPSTREAM_PACKAGE}}}",
    )
    assert absent == expected_absent, (
        f"DescribePackage on {_UPSTREAM_PACKAGE!r} before any fetch returned {absent!r}, expected "
        f"{expected_absent!r}; otherwise the defaulted origin configuration asserted below would "
        f"not be attributable to the fetch"
    )

    pm_status, pm_body = _http(ctx, package_url, token=token)
    assert pm_status == 200, (
        f"the packument fetch for {_UPSTREAM_PACKAGE!r} through public:npmjs returned "
        f"{pm_status!r}: {pm_body[:300]!r}"
    )
    packument = json.loads(pm_body)
    tarball_url = packument["versions"][_UPSTREAM_VERSION]["dist"]["tarball"]
    assert tarball_url.startswith(endpoint), (
        f"the advertised tarball url {tarball_url!r} does not route through this repository "
        f"{endpoint!r}; CodeArtifact must rewrite dist.tarball to its own endpoint"
    )
    tgz_status, upstream_bytes = _http(ctx, tarball_url, token=token)
    assert tgz_status == 200 and len(upstream_bytes) > 0, (
        f"the tarball fetch returned {tgz_status!r} and {len(upstream_bytes)} bytes, expected 200 "
        f"and a non-empty body — without a completed download nothing is ingested"
    )

    ingested = _poll(
        lambda: {v["version"] for v in _list_versions(ca, domain, repository, _UPSTREAM_PACKAGE)},
        lambda vs: _UPSTREAM_VERSION in vs, timeout_s=_INGEST_WAIT_SECONDS, interval_s=3.0,
        reason=f"{_UPSTREAM_PACKAGE}@{_UPSTREAM_VERSION} to be retained after the upstream fetch")
    assert ingested == {_UPSTREAM_VERSION}, (
        f"the repository holds versions {sorted(ingested)!r} after fetching one, expected exactly "
        f"[{_UPSTREAM_VERSION!r}]"
    )

    # Origin controls default from how the FIRST version entered the repository.
    restrictions = ca.describe_package(
        domain=domain, repository=repository, format="npm",
        package=_UPSTREAM_PACKAGE)["package"]["originConfiguration"]["restrictions"]
    assert restrictions == {"publish": "BLOCK", "upstream": "ALLOW"}, (
        f"a package whose first version arrived by ingestion reports origin restrictions "
        f"{restrictions!r}; the documented default derives from the entry path, so an ingested "
        f"package must be {{'publish': 'BLOCK', 'upstream': 'ALLOW'}} — nobody configured this"
    )

    private = _npm_tarball(_UPSTREAM_PACKAGE, _PRIVATE_VERSION, b"sim2real substituted payload\n")
    envelope = _npm_publish_envelope(_UPSTREAM_PACKAGE, _PRIVATE_VERSION, private)
    blocked_status, blocked_body = _http(ctx, package_url, method="PUT", token=token,
                                         content_type="application/json", body=envelope)
    expected_blocked = (
        400,
        '{"success":false,"error":"This package is configured to block new versions from being '
        'published."}',
    )
    assert (blocked_status, blocked_body.decode("utf-8", "replace")) == expected_blocked, (
        f"publishing {_UPSTREAM_PACKAGE}@{_PRIVATE_VERSION} into a repository where the package is "
        f"publish=BLOCK returned HTTP {blocked_status!r} with body {blocked_body[:300]!r}, expected "
        f"{expected_blocked!r}: a 400 (neither an auth 401 nor a routing 404) that says why the "
        f"publish was refused, so a blocked publish is distinguishable from an unrelated error"
    )

    still = {v["version"] for v in _list_versions(ca, domain, repository, _UPSTREAM_PACKAGE)}
    assert still == {_UPSTREAM_VERSION}, (
        f"after the refused publish the repository holds {sorted(still)!r}, expected the ingested "
        f"version alone — the blocked version must not have landed"
    )
    blocked_version = _rejection(lambda: ca.describe_package_version(
        domain=domain, repository=repository, format="npm", package=_UPSTREAM_PACKAGE,
        packageVersion=_PRIVATE_VERSION))
    expected_blocked_version = (
        "ResourceNotFoundException",
        f"The npm package '{_UPSTREAM_PACKAGE}' does not exist in repository '{repository}'.",
    )
    assert blocked_version == expected_blocked_version, (
        f"DescribePackageVersion for the blocked {_PRIVATE_VERSION} answered {blocked_version!r}, "
        f"expected {expected_blocked_version!r}"
    )

    relaxed = ca.put_package_origin_configuration(
        domain=domain, repository=repository, format="npm", package=_UPSTREAM_PACKAGE,
        restrictions={"publish": "ALLOW", "upstream": "ALLOW"})
    assert relaxed["originConfiguration"]["restrictions"] == \
        {"publish": "ALLOW", "upstream": "ALLOW"}, (
        f"PutPackageOriginConfiguration echoed "
        f"{relaxed['originConfiguration']['restrictions']!r}, expected both set to ALLOW"
    )
    allowed_status, allowed_body = _http(ctx, package_url, method="PUT", token=token,
                                         content_type="application/json", body=envelope)
    assert allowed_status == 200, (
        f"the IDENTICAL publish of {_UPSTREAM_PACKAGE}@{_PRIVATE_VERSION} still returned "
        f"{allowed_status!r} after publish was relaxed to ALLOW: {allowed_body[:300]!r}. Without "
        f"this beat the earlier refusal is indistinguishable from 'refuses every publish'"
    )

    both = {v["version"] for v in _list_versions(ca, domain, repository, _UPSTREAM_PACKAGE)}
    assert both == {_UPSTREAM_VERSION, _PRIVATE_VERSION}, (
        f"the repository holds {sorted(both)!r}, expected both the ingested "
        f"{_UPSTREAM_VERSION!r} and the locally published {_PRIVATE_VERSION!r}"
    )
    external = {v["version"] for v in _list_versions(ca, domain, repository, _UPSTREAM_PACKAGE,
                                                     originType="EXTERNAL")}
    assert external == {_UPSTREAM_VERSION}, (
        f"ListPackageVersions(originType='EXTERNAL') returned {sorted(external)!r}, expected only "
        f"the ingested {_UPSTREAM_VERSION!r} — the filter must partition, not echo the full list"
    )
    internal = {v["version"] for v in _list_versions(ca, domain, repository, _UPSTREAM_PACKAGE,
                                                     originType="INTERNAL")}
    assert internal == {_PRIVATE_VERSION}, (
        f"ListPackageVersions(originType='INTERNAL') returned {sorted(internal)!r}, expected only "
        f"the locally published {_PRIVATE_VERSION!r}"
    )
    assert external.isdisjoint(internal) and external | internal == both, (
        f"the two originType filters returned {sorted(external)!r} and {sorted(internal)!r}, which "
        f"do not partition the unfiltered {sorted(both)!r}"
    )

    ext_origin = ca.describe_package_version(
        domain=domain, repository=repository, format="npm", package=_UPSTREAM_PACKAGE,
        packageVersion=_UPSTREAM_VERSION)["packageVersion"]["origin"]
    assert ext_origin["originType"] == "EXTERNAL", (
        f"the ingested version reports originType {ext_origin['originType']!r}, expected EXTERNAL"
    )
    assert ext_origin["domainEntryPoint"]["externalConnectionName"] == "public:npmjs", (
        f"the ingested version's entry point is {ext_origin['domainEntryPoint']!r}, expected the "
        f"public:npmjs connection it came through"
    )
    int_origin = ca.describe_package_version(
        domain=domain, repository=repository, format="npm", package=_UPSTREAM_PACKAGE,
        packageVersion=_PRIVATE_VERSION)["packageVersion"]["origin"]
    assert int_origin["originType"] == "INTERNAL", (
        f"the locally published version reports originType {int_origin['originType']!r}, expected "
        f"INTERNAL"
    )
    assert "externalConnectionName" not in int_origin.get("domainEntryPoint", {}), (
        f"the locally published version names an external entry point "
        f"{int_origin.get('domainEntryPoint')!r}; a direct publish came through no connection"
    )

    # Terminal read: the bytes each version serves, at the endpoint, differ exactly as published —
    # so the partition above is about two genuinely distinct artifacts, not two labels on one.
    served_status, served = _http(ctx,
        endpoint + urllib.parse.quote(_UPSTREAM_PACKAGE, safe="")
        + f"/-/{_UPSTREAM_PACKAGE}-{_PRIVATE_VERSION}.tgz", token=token)
    assert served_status == 200, (
        f"the substituted version's tarball GET returned {served_status!r}: {served[:200]!r}"
    )
    assert served == private, (
        f"the endpoint served {len(served)} bytes (sha256 "
        f"{hashlib.sha256(served).hexdigest()!r}) for the locally published version; the check "
        f"published {len(private)} bytes (sha256 {hashlib.sha256(private).hexdigest()!r})"
    )
    assert served != upstream_bytes, (
        f"the locally published version and the ingested one serve identical bytes (sha256 "
        f"{hashlib.sha256(served).hexdigest()!r}); they are different artifacts and the originType "
        f"partition above would be meaningless if they were not"
    )


def _list_versions(ca, domain: str, repository: str, package: str, **extra) -> list[dict]:
    """Every page of ListPackageVersions for one npm package. Hard-subscripts `versions`: a
    response missing the key is a defect this check must surface, not default away."""
    out, next_token = [], None
    while True:
        page = ca.list_package_versions(
            domain=domain, repository=repository, format="npm", package=package, **extra,
            **({"nextToken": next_token} if next_token else {}))
        out.extend(page["versions"])
        next_token = page.get("nextToken")
        if not next_token:
            return out


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


def _rejection(fn) -> tuple[str, str]:
    """The (error code, message) of a call that MUST fail; raises if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to be rejected but returned {result!r}")


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


def _delete_package(ca, domain: str, repository: str, package: str) -> None:
    """DeletePackage, tolerating a package another cleanup step already removed."""
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
