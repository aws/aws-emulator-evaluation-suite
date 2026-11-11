"""e2e-external-connection-upstream-fetch-then-disassociate-blocks."""
from __future__ import annotations

import json
import re
import time
import urllib.request
from typing import Any, Callable

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "e2e-external-connection-upstream-fetch-then-disassociate-blocks"
GROUP = "overly-permissive"
SERVICES = ["codeartifact"]

# A stable, long-published npm package used purely as a fixture. Old published
# versions of npm packages are effectively immutable (npm disallows unpublishing
# after a short window), so pinning a specific old version is safe.
_NPM_PACKAGE = "lodash"
_CACHED_VERSION = "4.17.20"
_NEVER_FETCHED_VERSION = "4.17.19"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An external connection lets the npm repository endpoint pull an upstream version; after
    disassociating, the cached version stays downloadable via the API, but an upstream version
    never fetched while the connection was live can no longer be retrieved."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(
        domain=domain, repository=repository, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    ca.associate_external_connection(
        domain=domain, repository=repository, externalConnection="public:npmjs"
    )

    endpoint = ca.get_repository_endpoint(domain=domain, repository=repository, format="npm")[
        "repositoryEndpoint"
    ].rstrip("/")
    token = ca.get_authorization_token(domain=domain, durationSeconds=900)["authorizationToken"]

    # Mimic the npm client (GetPackageVersionAsset alone does not fetch upstream): GET the
    # packument, then the version's tarball URL it advertises, which pulls the version
    # through the external connection into CodeArtifact's own storage.
    packument = _http_get_json(ctx, f"{endpoint}/{_NPM_PACKAGE}", token)
    # Positive control for the claim below: while the connection is live, the packument
    # advertises a version that has never been individually fetched -- proving there IS a
    # live upstream path to it right now, so its later disappearance is attributable to
    # disassociation rather than to the version never having existed upstream at all.
    assert _NEVER_FETCHED_VERSION in packument["versions"], (
        f"expected the live external connection to advertise upstream version "
        f"{_NEVER_FETCHED_VERSION!r} in the packument; got {sorted(packument['versions'])!r}"
    )
    dist = packument["versions"][_CACHED_VERSION]["dist"]
    tarball_url = dist["tarball"]
    tarball_bytes = _http_get_bytes(ctx, tarball_url, token)
    assert len(tarball_bytes) > 0, f"expected pull-through tarball bytes, got {len(tarball_bytes)}"

    # CodeArtifact persists the pulled-through version asynchronously (docs:
    # typically ~3 minutes, occasionally longer). Wait for that persistence to
    # land before disassociating, so the "still available after disassociate"
    # check below is exercising real retained storage, not an in-flight cache.
    versions = _poll_until_condition(
        lambda: ca.list_package_versions(
            domain=domain, repository=repository, format="npm", package=_NPM_PACKAGE
        )["versions"],
        lambda vs: _CACHED_VERSION in {v["version"] for v in vs},
        timeout_s=240,
    )
    assert _CACHED_VERSION in {v["version"] for v in versions}, (
        f"expected {_CACHED_VERSION!r} to be persisted after the pull-through fetch; "
        f"got {sorted(v['version'] for v in versions)!r}"
    )

    ca.disassociate_external_connection(
        domain=domain, repository=repository, externalConnection="public:npmjs"
    )

    # The already-persisted version is still served from CodeArtifact's own
    # storage, independent of the (now-removed) external connection. Look up
    # the actual asset name CodeArtifact recorded for it rather than assuming
    # the upstream tarball naming convention.
    assets = ca.list_package_version_assets(
        domain=domain,
        repository=repository,
        format="npm",
        package=_NPM_PACKAGE,
        packageVersion=_CACHED_VERSION,
    )["assets"]
    assert assets, "expected at least one persisted asset for the cached version"
    cached_asset = assets[0]["name"]
    still_cached = ca.get_package_version_asset(
        domain=domain,
        repository=repository,
        format="npm",
        package=_NPM_PACKAGE,
        packageVersion=_CACHED_VERSION,
        asset=cached_asset,
    )
    still_cached_bytes = still_cached["asset"].read()
    assert len(still_cached_bytes) > 0, (
        f"expected the retained asset {cached_asset!r} to still serve bytes after "
        f"disassociation, got {len(still_cached_bytes)}"
    )

    # Same wiring as the positive control above, read again now the connection is gone: the
    # packument must reflect only what CodeArtifact itself retains -- there is no live upstream
    # left to keep advertising the version that was never individually pulled.
    packument_after = _http_get_json(ctx, f"{endpoint}/{_NPM_PACKAGE}", token)
    assert _CACHED_VERSION in packument_after["versions"], (
        f"expected the persisted version {_CACHED_VERSION!r} to remain in the packument "
        f"after disassociation; got {sorted(packument_after['versions'])!r}"
    )
    assert _NEVER_FETCHED_VERSION not in packument_after["versions"], (
        f"expected {_NEVER_FETCHED_VERSION!r} to disappear from the packument once the "
        f"external connection that was advertising it is gone; got "
        f"{sorted(packument_after['versions'])!r}"
    )

    # A different upstream version that was never pulled while the connection was
    # live can no longer be fetched -- there is no live path to the upstream
    # anymore, and CodeArtifact never persisted it.
    never_fetched_asset = f"{_NPM_PACKAGE}-{_NEVER_FETCHED_VERSION}.tgz"
    # The message embeds the repository's internal repoId, which no API returns; it is masked.
    code, message = _error(
        lambda: ca.get_package_version_asset(
            domain=domain,
            repository=repository,
            format="npm",
            package=_NPM_PACKAGE,
            packageVersion=_NEVER_FETCHED_VERSION,
            asset=never_fetched_asset,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException fetching a never-cached version after "
        f"disassociation, got {code!r}"
    )
    expected_message = (
        f"Package version not found in repo. repoId = '<id>', packageCoordinate = "
        f"'PackageVersionCoordinateEntity{{name={_NPM_PACKAGE}, type=NPM, version={_NEVER_FETCHED_VERSION}, "
        f"displayName={_NPM_PACKAGE}@{_NEVER_FETCHED_VERSION}}}'."
    )
    assert message == expected_message, f"the refusal said {message!r}, expected {expected_message!r}"
    versions_after = ca.list_package_versions(
        domain=domain, repository=repository, format="npm", package=_NPM_PACKAGE
    )["versions"]
    assert _NEVER_FETCHED_VERSION not in {v["version"] for v in versions_after}, (
        f"expected {_NEVER_FETCHED_VERSION!r} to be absent from ListPackageVersions; "
        f"got {sorted(v['version'] for v in versions_after)!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of a call that MUST be rejected, the internal id masked; raises if
    it unexpectedly succeeds."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), _mask_internal_id(error.get("Message", ""))
        raise
    raise AssertionError(f"expected the call to be rejected but it succeeded with {result!r}")


_INTERNAL_ID = re.compile(r"(repoId = '|domainId=)[0-9a-f-]{36}")


def _mask_internal_id(message: str) -> str:
    """Mask the service-internal repository or domain id, which no CodeArtifact API returns."""
    return _INTERNAL_ID.sub(r"\1<id>", message)


def _http_get_bytes(ctx, url: str, bearer_token: str, timeout_s: float = 30.0) -> bytes:
    req = _routed_request(ctx, url, headers={"Authorization": f"Bearer {bearer_token}"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
        return resp.read()


def _http_get_json(ctx, url: str, bearer_token: str, timeout_s: float = 30.0) -> dict:
    return json.loads(_http_get_bytes(ctx, url, bearer_token, timeout_s).decode("utf-8"))


def _poll_until_condition(
    fn: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float = 5.0
) -> Any:
    """Bounded retry: keep calling fn() until predicate(result) is true; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    result = fn()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"condition not satisfied within {timeout_s}s; last observation: {result!r}"
            )
        time.sleep(interval_s)
        result = fn()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

