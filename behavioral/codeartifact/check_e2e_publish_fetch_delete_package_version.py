"""e2e-publish-fetch-delete-package-version."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-publish-fetch-delete-package-version"
GROUP = "state-machine"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A published version's asset reads back byte-exact, a token and endpoint are issued, the
    version is listed, then deleted and gone, and the repository and domain delete cleanly."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-dom-")
    repo = ctx.unique_name("sim2real-behav-repo-")
    package = ctx.unique_name("sim2real-behav-pkg-")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    version = "1.0.0"
    fmt = "generic"
    content = b"sim2real e2e payload"
    sha256 = hashlib.sha256(content).hexdigest()
    resource_tags = [{"key": "sim2real", "value": CHECK}]

    domain_arn = ca.create_domain(domain=domain, tags=resource_tags)["domain"]["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: ca.delete_domain(domain=domain)))
    ca.create_repository(domain=domain, repository=repo, tags=resource_tags)
    ctx.on_cleanup(lambda: _safe(lambda: ca.delete_repository(domain=domain, repository=repo)))

    ca.publish_package_version(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=version,
        assetContent=content,
        assetName="payload.bin",
        assetSHA256=sha256,
    )

    fetched = ca.get_package_version_asset(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        packageVersion=version,
        asset="payload.bin",
    )
    served = fetched["asset"].read()
    assert served == content, (
        f"the fetched asset is {len(served)} bytes with sha256 "
        f"{hashlib.sha256(served).hexdigest()!r}, expected {len(content)} bytes with "
        f"{sha256!r} — the published payload must come back byte-exact"
    )
    assert fetched.get("assetName") == "payload.bin", (
        f"the fetch echoed assetName {fetched.get('assetName')!r}, expected 'payload.bin'"
    )

    request_time = datetime.now(timezone.utc)
    duration_s = 900
    token_resp = ca.get_authorization_token(domain=domain, durationSeconds=duration_s)
    assert token_resp.get("authorizationToken"), "get_authorization_token returned an empty token"
    expiration = token_resp.get("expiration")
    assert expiration is not None, "get_authorization_token returned no expiration"
    assert request_time < expiration <= request_time + timedelta(
        seconds=duration_s + 60
    ), (
        f"the token expires at {expiration.isoformat()}, expected it to fall "
        f"between now ({request_time.isoformat()}) and now+{duration_s}s (plus slack) — it "
        f"must honor the requested durationSeconds, not just lie in the future"
    )

    endpoint = ca.get_repository_endpoint(domain=domain, repository=repo, format=fmt)[
        "repositoryEndpoint"
    ]
    parsed = urlparse(endpoint)
    assert parsed.scheme in ("http", "https") and parsed.netloc, (
        f"the repository endpoint is {endpoint!r}, expected an absolute http(s) URL"
    )
    # The host is environment-dependent; only the path naming the repository is graded.
    assert repo in parsed.path, (
        f"the repository endpoint is {endpoint!r}, expected a URL path naming the "
        f"repository {repo!r} it was minted for"
    )

    versions = ca.list_package_versions(
        domain=domain, repository=repo, format=fmt, namespace=namespace, package=package
    )["versions"]
    assert {v["version"] for v in versions} == {version}, (
        f"list_package_versions returned {[v['version'] for v in versions]!r}, expected "
        f"exactly [{version!r}]"
    )

    delete_result = ca.delete_package_versions(
        domain=domain,
        repository=repo,
        format=fmt,
        namespace=namespace,
        package=package,
        versions=[version],
    )
    assert version in delete_result["successfulVersions"], (
        f"delete_package_versions reported successfulVersions="
        f"{delete_result['successfulVersions']!r}, expected {version!r} among them"
    )
    assert delete_result["successfulVersions"][version]["status"] == "Deleted", (
        f"delete_package_versions marked {version!r} as "
        f"{delete_result['successfulVersions'][version]['status']!r}, expected 'Deleted'"
    )

    remaining = ca.list_package_versions(
        domain=domain, repository=repo, format=fmt, namespace=namespace, package=package
    )["versions"]
    assert remaining == [], (
        f"list_package_versions still returned {remaining!r} after delete, expected []"
    )
    _assert_not_found(
        _error(lambda: ca.get_package_version_asset(
            domain=domain, repository=repo, format=fmt, namespace=namespace, package=package,
            packageVersion=version, asset="payload.bin",
        )),
        "get_package_version_asset on the deleted version",
    )

    ca.delete_repository(domain=domain, repository=repo)
    _assert_not_found(
        _error(lambda: ca.describe_repository(domain=domain, repository=repo)),
        "describe_repository on a deleted repository",
    )
    repos = _pages(ca.list_repositories_in_domain, "repositories", domain=domain)
    assert repo not in {r["name"] for r in repos}, (
        f"the deleted repository is still in list_repositories_in_domain ({len(repos)} repositories)"
    )
    _assert_not_found(
        _error(lambda: ca.update_repository(domain=domain, repository=repo, description="x")),
        "update_repository on a deleted repository",
    )

    ca.delete_domain(domain=domain)
    _assert_not_found(
        _error(lambda: ca.describe_domain(domain=domain)), "describe_domain on a deleted domain"
    )
    domains = _pages(ca.list_domains, "domains")
    assert domain not in {d["name"] for d in domains}, (
        f"the deleted domain is still in list_domains ({len(domains)} domains)"
    )
    _assert_not_found(
        _error(lambda: ca.tag_resource(resourceArn=domain_arn, tags=resource_tags)),
        "tag_resource on a deleted domain",
    )


def _error(fn):
    """Call fn(); return its (error code, message, HTTP status). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"].get("Code"),
            exc.response["Error"].get("Message") or "",
            exc.response["ResponseMetadata"]["HTTPStatusCode"],
        )
    raise AssertionError(f"expected this call to fail with not-found, but it SUCCEEDED: {result!r}")


def _assert_not_found(err, what: str) -> None:
    """ResourceNotFoundException, HTTP 404, and a non-empty message (AWS's wording may name the
    resource or a service-internal id, so the message is not matched)."""
    code, message, status = err
    assert code == "ResourceNotFoundException", (
        f"{what} raised {code!r}, expected 'ResourceNotFoundException'"
    )
    assert status == 404, f"{what} answered HTTP {status}, expected 404"
    assert message, f"{what} carried an empty message"


def _pages(fn, key: str, **kwargs) -> list:
    """Every item under `key` across every page of a CodeArtifact list operation."""
    items, token = [], None
    while True:
        page = fn(**({**kwargs, "nextToken": token} if token else kwargs))
        items.extend(page.get(key) or [])
        token = page.get("nextToken")
        if not token:
            return items


def _safe(fn) -> None:
    """Teardown that tolerates only the resource already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
