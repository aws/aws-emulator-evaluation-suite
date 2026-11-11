"""package-origin-configuration-blocks-upstream-ingestion."""
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

CHECK = "package-origin-configuration-blocks-upstream-ingestion"
GROUP = "server-side"
SERVICES = ["codeartifact"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """upstream=BLOCK on a never-seen package stops its ingestion from public PyPI even after a real
    index-plus-wheel download; an unrestricted sibling is ingested normally as a positive control.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-caorigin-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    repo = ctx.unique_name("repo-")
    ca.create_repository(domain=domain, repository=repo,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))
    ca.associate_external_connection(
        domain=domain, repository=repo, externalConnection="public:pypi"
    )

    blocked_pkg = "six"
    allowed_pkg = "toml"

    ca.put_package_origin_configuration(
        domain=domain,
        repository=repo,
        format="pypi",
        package=blocked_pkg,
        restrictions={"publish": "BLOCK", "upstream": "BLOCK"},
    )

    endpoint = ctx.endpoint_url(
        ca.get_repository_endpoint(domain=domain, repository=repo, format="pypi")["repositoryEndpoint"]
    )
    token = ca.get_authorization_token(domain=domain)["authorizationToken"]

    _pip_download(ctx, endpoint, blocked_pkg, token)
    _pip_download(ctx, endpoint, allowed_pkg, token)

    versions = _list_versions_safe(ca, domain, repo, blocked_pkg)
    assert versions == [], f"blocked package unexpectedly ingested a version: {versions}"

    # External-connection ingestion typically takes ~3 minutes and occasionally longer.
    ingested: list = []
    deadline = time.monotonic() + _budget_s(ctx, _INGEST_BUDGET_S)
    next_trigger = time.monotonic() + _RETRIGGER_S
    while time.monotonic() < deadline:
        ingested = _list_versions_safe(ca, domain, repo, allowed_pkg)
        if ingested:
            break
        if time.monotonic() >= next_trigger:
            _pip_download(ctx, endpoint, allowed_pkg, token)
            next_trigger = time.monotonic() + _RETRIGGER_S
        time.sleep(_POLL_S)
    if not ingested and _budget_spent(ctx):
        raise TimeoutError("control package ingested from the upstream connection: the run budget ended first; not graded")
    assert ingested, "control package was never ingested from the upstream connection"

    final_blocked_versions = _list_versions_safe(ca, domain, repo, blocked_pkg)
    assert final_blocked_versions == [], (
        f"blocked package gained a version after control ingestion succeeded: "
        f"{final_blocked_versions}"
    )

    absent = _error(
        lambda: ca.get_package_version_asset(
            domain=domain,
            repository=repo,
            format="pypi",
            package=blocked_pkg,
            packageVersion="1.0.0",
            asset=f"{blocked_pkg}-1.0.0.tar.gz",
        )
    )
    # The message embeds the service-internal repository id, which no API returns; it is masked.
    expected_absent = (
        "ResourceNotFoundException",
        f"Package version not found in repo. repoId = '<id>', packageCoordinate = "
        f"'PackageVersionCoordinateEntity{{name={blocked_pkg}, type=PYPI, version=1.0.0, "
        f"displayName={blocked_pkg}==1.0.0}}'.",
    )
    assert absent == expected_absent, (
        f"expected no asset for the blocked package ({expected_absent!r}), got {absent!r}"
    )


_INGEST_BUDGET_S = 300.0
_RETRIGGER_S = 10.0
_POLL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _auth_header(token: str) -> str:
    basic = base64.b64encode(f"aws:{token}".encode("utf-8")).decode("ascii")
    return f"Basic {basic}"


def _pip_download(ctx, endpoint: str, package_name: str, token: str) -> None:
    """Best-effort ingestion trigger: resolve the Simple Repository API JSON index, then
    download one concrete file from it, as `pip install` does.
    """
    index_url = endpoint.rstrip("/") + f"/simple/{package_name}/"
    req = urllib.request.Request(index_url)
    req.add_header("Authorization", _auth_header(token))
    req.add_header("Accept", "application/vnd.pypi.simple.v1+json")
    try:
        with urllib.request.urlopen(req, timeout=_budget_s(ctx, 30.0)) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError):
        return

    files = body.get("files") or []
    if not files:
        return
    file_url = files[0].get("url")
    if not file_url:
        return
    resolved = urllib.parse.urljoin(index_url, file_url)
    freq = urllib.request.Request(resolved)
    freq.add_header("Authorization", _auth_header(token))
    try:
        with urllib.request.urlopen(freq, timeout=_budget_s(ctx, 60.0)) as resp:
            resp.read()
    except urllib.error.URLError:
        pass


def _list_versions_safe(ca, domain: str, repo: str, package: str) -> list:
    """ListPackageVersions; ResourceNotFoundException (never-ingested pypi package) counts as empty."""
    try:
        return ca.list_package_versions(
            domain=domain, repository=repo, format="pypi", package=package
        ).get("versions", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message), the internal id masked. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], _mask_internal_id(error.get("Message", ""))
    raise AssertionError(f"the call SUCCEEDED where real AWS refuses it and returned {result!r}")


_INTERNAL_ID = re.compile(r"(repoId = '|domainId=)[0-9a-f-]{36}")


def _mask_internal_id(message: str) -> str:
    """Mask the service-internal repository or domain id, which no CodeArtifact API returns."""
    return _INTERNAL_ID.sub(r"\1<id>", message)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

