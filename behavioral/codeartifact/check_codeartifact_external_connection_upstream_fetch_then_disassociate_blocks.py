"""codeartifact-external-connection-upstream-fetch-then-disassociate-blocks."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "codeartifact-external-connection-upstream-fetch-then-disassociate-blocks"
GROUP = 'overly-permissive'
SERVICES = ['codeartifact']

# A long-published npm package used purely as a fixture. npm forbids unpublishing after a short
# window, so a pinned old version is stable for a long-lived fidelity check.
_NPM_PACKAGE = "lodash"
_CACHED_VERSION = "4.17.20"
_NEVER_FETCHED_VERSION = "4.17.19"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """After an npm version is pulled through an external connection and the connection is removed,
    the cached version's asset still serves the same bytes, while a never-pulled sibling version
    fails with the exact ResourceNotFoundException until the connection is restored."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))
    ca.associate_external_connection(domain=domain, repository=repository,
                                     externalConnection="public:npmjs")

    endpoint = ca.get_repository_endpoint(domain=domain, repository=repository,
                                          format="npm")["repositoryEndpoint"]
    token = ca.get_authorization_token(domain=domain,
                                       durationSeconds=900)["authorizationToken"]

    # Exactly what the npm client does: GET the packument, then GET the version's tarball URL.
    # That second request is what pulls the version through the connection into CodeArtifact.
    pm_status, pm_body = _http(ctx, endpoint + _NPM_PACKAGE, token)
    assert pm_status == 200, (
        f"the packument for {_NPM_PACKAGE!r} through the external connection returned "
        f"{pm_status!r}: {pm_body[:300]!r}"
    )
    packument = json.loads(pm_body)
    assert _CACHED_VERSION in packument["versions"], (
        f"the upstream packument does not advertise the pinned fixture version "
        f"{_CACHED_VERSION!r}; it offers {len(packument['versions'])!r} versions"
    )
    tarball_url = packument["versions"][_CACHED_VERSION]["dist"]["tarball"]
    assert tarball_url.startswith(endpoint), (
        f"the tarball URL bypasses the repository endpoint {endpoint!r}: {tarball_url!r}"
    )
    tgz_status, tarball_bytes = _http(ctx, tarball_url, token)
    assert tgz_status == 200 and len(tarball_bytes) > 0, (
        f"the pull-through tarball GET returned {tgz_status!r} with {len(tarball_bytes)!r} bytes"
    )

    # Persistence is asynchronous. Wait for it, so the "still available after disassociate" leg
    # is exercising retained storage rather than an in-flight fetch.
    cached = _poll(
        lambda: {v["version"] for v in _list_versions(ca, domain, repository, _NPM_PACKAGE)},
        lambda versions: _CACHED_VERSION in versions, timeout_s=180.0, interval_s=3.0)
    assert _CACHED_VERSION in cached, (
        f"the pulled-through version was never persisted in the repository: "
        f"ListPackageVersions reported {sorted(cached)!r}"
    )

    ca.disassociate_external_connection(domain=domain, repository=repository,
                                        externalConnection="public:npmjs")

    # Positive control: the persisted version is still readable from CodeArtifact's own storage,
    # independent of the connection that is now gone.
    assets = _paginate(ca.list_package_version_assets, "assets", domain=domain,
                      repository=repository, format="npm", package=_NPM_PACKAGE,
                      packageVersion=_CACHED_VERSION)
    assert assets, (
        f"no persisted asset for {_NPM_PACKAGE}@{_CACHED_VERSION} after disassociation"
    )
    still_cached = ca.get_package_version_asset(
        domain=domain, repository=repository, format="npm", package=_NPM_PACKAGE,
        packageVersion=_CACHED_VERSION, asset=assets[0]["name"])["asset"].read()
    assert still_cached == tarball_bytes, (
        f"the retained asset is {len(still_cached)!r} bytes, the pull-through served "
        f"{len(tarball_bytes)!r}"
    )

    # A sibling version that was never pulled while the connection was live has no path left.
    # The message embeds the repository's internal repoId, which no API returns; it is masked.
    code, message = _rejection(lambda: ca.get_package_version_asset(
        domain=domain, repository=repository, format="npm", package=_NPM_PACKAGE,
        packageVersion=_NEVER_FETCHED_VERSION,
        asset=f"{_NPM_PACKAGE}-{_NEVER_FETCHED_VERSION}.tgz"))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a version never pulled before the connection "
        f"was removed, got {code!r}"
    )
    expected_message = (
        f"Package version not found in repo. repoId = '<id>', packageCoordinate = "
        f"'PackageVersionCoordinateEntity{{name={_NPM_PACKAGE}, type=NPM, version={_NEVER_FETCHED_VERSION}, "
        f"displayName={_NPM_PACKAGE}@{_NEVER_FETCHED_VERSION}}}'."
    )
    assert message == expected_message, f"the refusal said {message!r}, expected {expected_message!r}"
    remaining = {v["version"] for v in _list_versions(ca, domain, repository, _NPM_PACKAGE)}
    assert _NEVER_FETCHED_VERSION not in remaining, (
        f"a never-fetched version appeared in the repository after disassociation: "
        f"{sorted(remaining)!r}"
    )
    assert _CACHED_VERSION in remaining, (
        f"disassociation removed the cached version too: {sorted(remaining)!r}"
    )

    # Restore: the block is the connection's absence, not a property of the version itself.
    # Reassociating and repeating the IDENTICAL fetch that was just rejected must now succeed.
    ca.associate_external_connection(domain=domain, repository=repository,
                                     externalConnection="public:npmjs")
    pm_status2, pm_body2 = _http(ctx, endpoint + _NPM_PACKAGE, token)
    assert pm_status2 == 200, (
        f"the packument for {_NPM_PACKAGE!r} returned {pm_status2!r} after reassociation: "
        f"{pm_body2[:300]!r}"
    )
    packument2 = json.loads(pm_body2)
    assert _NEVER_FETCHED_VERSION in packument2["versions"], (
        f"the upstream packument no longer advertises {_NEVER_FETCHED_VERSION!r} after "
        f"reassociation; it offers {sorted(packument2['versions'])!r}"
    )
    tarball_url2 = packument2["versions"][_NEVER_FETCHED_VERSION]["dist"]["tarball"]
    tgz_status2, tarball_bytes2 = _http(ctx, tarball_url2, token)
    assert tgz_status2 == 200 and len(tarball_bytes2) > 0, (
        f"the pull-through tarball GET for the previously-blocked version returned "
        f"{tgz_status2!r} with {len(tarball_bytes2)!r} bytes after reassociation"
    )
    restored = _poll(
        lambda: {v["version"] for v in _list_versions(ca, domain, repository, _NPM_PACKAGE)},
        lambda versions: _NEVER_FETCHED_VERSION in versions, timeout_s=180.0, interval_s=3.0)
    assert _NEVER_FETCHED_VERSION in restored, (
        f"the previously-blocked version was fetched successfully but never persisted: "
        f"ListPackageVersions reported {sorted(restored)!r}"
    )


def _http(ctx, url: str, token: str, timeout_s: float = 60.0) -> tuple[int, bytes]:
    """One npm-registry-protocol GET, returning (status, body) for any HTTP status."""
    req = _routed_request(ctx, url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


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


def _list_versions(ca, domain: str, repository: str, package: str) -> list[dict]:
    """Every page of ListPackageVersions, tolerating the not-yet-ingested package."""
    out, next_token = [], None
    while True:
        try:
            page = ca.list_package_versions(
                domain=domain, repository=repository, format="npm", package=package,
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
