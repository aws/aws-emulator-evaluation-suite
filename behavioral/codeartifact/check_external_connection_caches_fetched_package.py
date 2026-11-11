"""external-connection-caches-fetched-package."""
from __future__ import annotations

import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "external-connection-caches-fetched-package"
GROUP = 'external-connections'
SERVICES = ['codeartifact']

_EXTERNAL_PACKAGE = "left-pad"
_EXTERNAL_VERSION = "1.3.0"


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS is a hard
    failure."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"the call SUCCEEDED where real AWS rejects it and returned {result!r}"
    )


def _disassociate_if_associated(ca, domain, repo, connection):
    """Teardown: the check body disassociates the connection itself, so an already-removed
    connection is the expected end state here."""
    try:
        ca.disassociate_external_connection(
            domain=domain, repository=repo, externalConnection=connection)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_domain(ca, domain, deadline=90.0):
    """DeleteDomain, retrying while a repository this check already deleted still counts."""
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


def _fetch(ctx, endpoint, token, path):
    """GET a path under the repository endpoint with the domain bearer token."""
    req = _routed_request(ctx, endpoint.rstrip("/") + path,
                                 headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.status, resp.read()


def _versions(ca, domain, repo):
    out = []
    for page in ca.get_paginator("list_package_versions").paginate(
            domain=domain, repository=repo, format="npm", package=_EXTERNAL_PACKAGE):
        out.extend(page["versions"])
    return out


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An npm fetch through a public:npmjs external connection caches the version with an EXTERNAL
    origin naming public:npmjs, the package is unknown before the fetch, and the cached version stays
    after the connection is disassociated."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-npm-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    associated = ca.associate_external_connection(
        domain=domain, repository=repo, externalConnection="public:npmjs")["repository"]
    ctx.on_cleanup(lambda: _disassociate_if_associated(ca, domain, repo, "public:npmjs"))
    assert [c["externalConnectionName"] for c in associated["externalConnections"]] == \
        ["public:npmjs"], (
        f"the repository reports connections {associated['externalConnections']!r}, "
        f"expected exactly public:npmjs"
    )

    absent = _error(lambda: ca.describe_package(
        domain=domain, repository=repo, format="npm", package=_EXTERNAL_PACKAGE))
    expected_absent = (
        "ResourceNotFoundException",
        f"Package not found in repository. Package = {{format=npm, name={_EXTERNAL_PACKAGE}}}",
    )
    assert absent == expected_absent, (
        f"before any fetch DescribePackage on {_EXTERNAL_PACKAGE!r} returned {absent!r}, expected "
        f"{expected_absent!r} — an external connection must not populate the repository on its own"
    )

    endpoint = ca.get_repository_endpoint(
        domain=domain, repository=repo, format="npm")["repositoryEndpoint"]
    token = ca.get_authorization_token(domain=domain, durationSeconds=900)["authorizationToken"]

    status, body = _fetch(ctx, endpoint, token, "/" + _EXTERNAL_PACKAGE)
    assert status == 200, f"the packument fetch returned HTTP {status!r}, expected 200"
    packument = json.loads(body)
    assert packument["name"] == _EXTERNAL_PACKAGE, (
        f"the packument names {packument.get('name')!r}, expected {_EXTERNAL_PACKAGE!r}"
    )
    tarball = packument["versions"][_EXTERNAL_VERSION]["dist"]["tarball"]
    assert repo in tarball, (
        f"the packument's tarball url {tarball!r} does not route through this repository — "
        f"CodeArtifact must rewrite dist.tarball to its own endpoint"
    )
    status, tar = _fetch(ctx, endpoint, token, tarball.split(repo, 1)[1])
    assert status == 200 and len(tar) > 0, (
        f"the tarball fetch returned HTTP {status!r} and {len(tar)} bytes, expected 200 and bytes"
    )

    deadline = time.time() + 120
    cached = []
    while time.time() < deadline:
        cached = _versions(ca, domain, repo)
        if cached:
            break
        time.sleep(3)
    assert [v["version"] for v in cached] == [_EXTERNAL_VERSION], (
        f"after the fetch the repository holds versions "
        f"{[v['version'] for v in cached]!r}, expected exactly ['{_EXTERNAL_VERSION}']"
    )
    origin = cached[0]["origin"]
    assert origin["originType"] == "EXTERNAL", (
        f"the cached version's originType is {origin['originType']!r}, expected EXTERNAL"
    )
    assert origin["domainEntryPoint"]["externalConnectionName"] == "public:npmjs", (
        f"the cached version's entry point is {origin['domainEntryPoint']!r}, "
        f"expected the public:npmjs connection"
    )

    after = ca.disassociate_external_connection(
        domain=domain, repository=repo, externalConnection="public:npmjs")["repository"]
    assert after["externalConnections"] == [], (
        f"after disassociation the repository still reports {after['externalConnections']!r}"
    )
    still = _versions(ca, domain, repo)
    assert [v["version"] for v in still] == [_EXTERNAL_VERSION], (
        f"removing the connection dropped the cached copy: the repository now holds "
        f"{[v['version'] for v in still]!r}, expected the cache to survive"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
