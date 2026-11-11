"""codeartifact-package-origin-configuration-blocks-upstream-ingestion."""
from __future__ import annotations

import base64
import json
import re
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


CHECK = "codeartifact-package-origin-configuration-blocks-upstream-ingestion"
GROUP = 'overly-permissive'
SERVICES = ['codeartifact']

_BLOCKED_PACKAGE = "six"
_CONTROL_PACKAGE = "toml"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """With upstream=BLOCK, a PEP 503 index resolution and file download for a project ingest no
    version (GetPackageVersionAsset: exact ResourceNotFoundException), while an unrestricted sibling
    resolved over the same connection is ingested."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-caorigin-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))
    ca.associate_external_connection(domain=domain, repository=repository,
                                     externalConnection="public:pypi")

    # Break exactly one thing, pre-emptively, before any version of it has ever landed here.
    ca.put_package_origin_configuration(
        domain=domain, repository=repository, format="pypi", package=_BLOCKED_PACKAGE,
        restrictions={"publish": "BLOCK", "upstream": "BLOCK"})
    restrictions = ca.describe_package(
        domain=domain, repository=repository, format="pypi",
        package=_BLOCKED_PACKAGE)["package"]["originConfiguration"]["restrictions"]
    assert restrictions["upstream"] == "BLOCK", (
        f"the origin restriction did not take: {restrictions!r}"
    )

    endpoint = ca.get_repository_endpoint(domain=domain, repository=repository,
                                          format="pypi")["repositoryEndpoint"]
    basic = "Basic " + base64.b64encode(
        f"aws:{ca.get_authorization_token(domain=domain)['authorizationToken']}".encode()).decode()

    # The control package proves the whole fetch mechanism works, endpoint and upstream both.
    control_index, control_files = _pip_resolve(ctx, endpoint, _CONTROL_PACKAGE, basic)
    assert control_index == 200 and control_files, (
        f"the control project's index returned {control_index!r} with {control_files!r} files, so "
        f"nothing can be concluded from the blocked project's absence"
    )
    control_download = _pip_download(ctx, endpoint, _CONTROL_PACKAGE, control_files[0], basic)
    assert control_download[0] == 200 and len(control_download[1]) > 0, (
        f"the control project's file download returned {control_download[0]!r} with "
        f"{len(control_download[1])!r} bytes"
    )

    blocked_index, blocked_files = _pip_resolve(ctx, endpoint, _BLOCKED_PACKAGE, basic)
    if blocked_files:
        # If the endpoint does advertise files for the blocked project, ask for one: an
        # over-permissive implementation would ingest it here.
        _pip_download(ctx, endpoint, _BLOCKED_PACKAGE, blocked_files[0], basic)

    ingested = _poll(lambda: _versions(ca, domain, repository, _CONTROL_PACKAGE),
                     lambda vs: bool(vs), timeout_s=120.0, interval_s=3.0)
    assert ingested, (
        f"the control project was never ingested from the upstream connection, so the blocked "
        f"project's absence proves nothing (blocked index status was {blocked_index!r})"
    )

    # Effect absent: the blocked project holds nothing, after the control has proven ingestion.
    blocked_versions = _versions(ca, domain, repository, _BLOCKED_PACKAGE)
    assert blocked_versions == set(), (
        f"the origin-restricted project ingested {sorted(blocked_versions)!r} even though "
        f"upstream=BLOCK; the control project ingested {sorted(ingested)!r} in the same run"
    )
    # The message embeds the repository's internal repoId, which no API returns; it is masked.
    code, message = _rejection(lambda: ca.get_package_version_asset(
        domain=domain, repository=repository, format="pypi", package=_BLOCKED_PACKAGE,
        packageVersion="1.16.0", asset=f"{_BLOCKED_PACKAGE}-1.16.0.tar.gz"))
    assert code == "ResourceNotFoundException", (
        f"an asset exists for the origin-restricted project: GetPackageVersionAsset answered "
        f"{code!r}"
    )
    expected_message = (
        f"Package version not found in repo. repoId = '<id>', packageCoordinate = "
        f"'PackageVersionCoordinateEntity{{name={_BLOCKED_PACKAGE}, type=PYPI, version=1.16.0, "
        f"displayName={_BLOCKED_PACKAGE}==1.16.0}}'."
    )
    assert message == expected_message, f"the refusal said {message!r}, expected {expected_message!r}"
    assert ca.describe_package(
        domain=domain, repository=repository, format="pypi",
        package=_BLOCKED_PACKAGE)["package"]["originConfiguration"]["restrictions"][
            "upstream"] == "BLOCK", (
        "the upstream restriction was cleared by the resolution attempt"
    )


def _http(ctx, url: str, basic: str, accept: str | None = None,
          timeout_s: float = 60.0) -> tuple[int, bytes]:
    """One pypi-protocol GET. A transport failure raises: it is not an absence of ingestion."""
    headers = {"Authorization": basic}
    if accept:
        headers["Accept"] = accept
    req = _routed_request(ctx, url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _pip_resolve(ctx, endpoint: str, project: str, basic: str) -> tuple[int, list[str]]:
    """Resolve the PEP 691 JSON simple index for a project, as pip does."""
    status, body = _http(ctx, endpoint.rstrip("/") + f"/simple/{project}/", basic,
                         accept="application/vnd.pypi.simple.v1+json")
    if status != 200:
        return status, []
    return status, [f["url"] for f in (json.loads(body).get("files") or []) if f.get("url")]


def _pip_download(ctx, endpoint: str, project: str, href: str, basic: str) -> tuple[int, bytes]:
    """Download one concrete file the index advertised, as pip does after resolving."""
    index_url = endpoint.rstrip("/") + f"/simple/{project}/"
    return _http(ctx, urllib.parse.urljoin(index_url, href), basic)


def _rejection(fn) -> tuple[str, str]:
    """The (code, message) of a call that MUST be rejected, the internal id masked; raises if
    it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], _mask_internal_id(error.get("Message", ""))
    raise AssertionError(f"the call was expected to be rejected but returned {result!r}")


_INTERNAL_ID = re.compile(r"(repoId = '|domainId=)[0-9a-f-]{36}")


def _mask_internal_id(message: str) -> str:
    """Mask the service-internal repository or domain id, which no CodeArtifact API returns."""
    return _INTERNAL_ID.sub(r"\1<id>", message)


def _versions(ca, domain: str, repository: str, package: str) -> set[str]:
    """Every page of ListPackageVersions; a never-ingested pypi package reads as empty."""
    out, next_token = set(), None
    while True:
        try:
            page = ca.list_package_versions(
                domain=domain, repository=repository, format="pypi", package=package,
                **({"nextToken": next_token} if next_token else {}))
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return out
            raise
        out.update(v["version"] for v in page.get("versions", []))
        next_token = page.get("nextToken")
        if not next_token:
            return out


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
