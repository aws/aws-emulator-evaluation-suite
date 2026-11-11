"""package-group-origin-restriction-inherits-from-parent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-group-origin-restriction-inherits-from-parent"
GROUP = 'package-groups'
SERVICES = ['codeartifact']



_RESTRICTIONS = ("EXTERNAL_UPSTREAM", "INTERNAL_UPSTREAM", "PUBLISH")


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"the call SUCCEEDED where real AWS rejects it and returned {result!r}"
    )


def _delete_domain(ca, domain, deadline=90.0):
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


def _restrictions(ca, domain, pattern):
    return ca.describe_package_group(
        domain=domain, packageGroup=pattern)["packageGroup"]["originConfiguration"]["restrictions"]


def _allowed(ca, domain, pattern, kind):
    out = []
    for page in ca.get_paginator("list_allowed_repositories_for_group").paginate(
            domain=domain, packageGroup=pattern, originRestrictionType=kind):
        out.extend(page["allowedRepositories"])
    return sorted(out)


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A fresh group's origin restriction is INHERIT, resolved from and naming its ancestor; setting
    ALLOW_SPECIFIC_REPOSITORIES makes mode and effectiveMode agree, and INHERIT restores the ancestor.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    group = "/generic/sim2real-scope/*"

    created_tags = [{"key": "sim2real-check", "value": CHECK}]
    ca.create_domain(domain=domain, tags=created_tags)
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo, tags=created_tags)
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))
    ca.create_package_group(domain=domain, packageGroup=group, tags=created_tags)
    ctx.on_cleanup(lambda: ca.delete_package_group(domain=domain, packageGroup=group))

    fresh = _restrictions(ca, domain, group)
    for kind in _RESTRICTIONS:
        assert fresh[kind]["mode"] == "INHERIT", (
            f"a fresh group's {kind} mode is {fresh[kind]['mode']!r}, expected INHERIT"
        )
        assert fresh[kind]["effectiveMode"] == "ALLOW", (
            f"a fresh group's {kind} effectiveMode is {fresh[kind]['effectiveMode']!r}; the root "
            f"group allows everything, so the inherited answer must be ALLOW"
        )
        assert fresh[kind]["inheritedFrom"]["pattern"] == "/*", (
            f"a fresh group's {kind} says it inherited from "
            f"{fresh[kind]['inheritedFrom']!r}, expected the root group '/*'"
        )

    # While the mode is INHERIT there is no list to read at all, and the service says so rather
    # than answering with an empty collection.
    expected = (
        "ValidationException",
        "OriginRestrictionMode is not ALLOW_SPECIFIC_REPOSITORIES for the given OriginControlType",
    )
    refusal = _error(lambda: _allowed(ca, domain, group, "EXTERNAL_UPSTREAM"))
    assert refusal == expected, (
        f"listing allowed repositories for an INHERIT restriction returned {refusal!r}, expected "
        f"{expected!r} rather than an empty list"
    )

    ca.update_package_group_origin_configuration(
        domain=domain, packageGroup=group,
        restrictions={"EXTERNAL_UPSTREAM": "ALLOW_SPECIFIC_REPOSITORIES"},
        addAllowedRepositories=[{"repositoryName": repo,
                                 "originRestrictionType": "EXTERNAL_UPSTREAM"}])

    pinned = _restrictions(ca, domain, group)
    assert pinned["EXTERNAL_UPSTREAM"]["mode"] == "ALLOW_SPECIFIC_REPOSITORIES", (
        f"after the update EXTERNAL_UPSTREAM mode is "
        f"{pinned['EXTERNAL_UPSTREAM']['mode']!r}, expected ALLOW_SPECIFIC_REPOSITORIES"
    )
    assert pinned["EXTERNAL_UPSTREAM"]["effectiveMode"] == "ALLOW_SPECIFIC_REPOSITORIES", (
        f"the effectiveMode is {pinned['EXTERNAL_UPSTREAM']['effectiveMode']!r}; once a mode is "
        f"set explicitly the two must agree"
    )
    assert "inheritedFrom" not in pinned["EXTERNAL_UPSTREAM"], (
        f"an explicitly set restriction still reports "
        f"inheritedFrom={pinned['EXTERNAL_UPSTREAM'].get('inheritedFrom')!r}"
    )
    assert pinned["EXTERNAL_UPSTREAM"]["repositoriesCount"] == 1, (
        f"the allowed-repository count is "
        f"{pinned['EXTERNAL_UPSTREAM'].get('repositoriesCount')!r}, expected 1"
    )
    assert pinned["INTERNAL_UPSTREAM"]["mode"] == "INHERIT", (
        f"setting EXTERNAL_UPSTREAM also changed INTERNAL_UPSTREAM to "
        f"{pinned['INTERNAL_UPSTREAM']['mode']!r}; the three restrictions are independent"
    )
    assert _allowed(ca, domain, group, "EXTERNAL_UPSTREAM") == [repo], (
        f"the allowed-repository listing returned "
        f"{_allowed(ca, domain, group, 'EXTERNAL_UPSTREAM')!r}, expected [{repo!r}]"
    )

    ca.update_package_group_origin_configuration(
        domain=domain, packageGroup=group,
        removeAllowedRepositories=[{"repositoryName": repo,
                                    "originRestrictionType": "EXTERNAL_UPSTREAM"}])
    ca.update_package_group_origin_configuration(
        domain=domain, packageGroup=group, restrictions={"EXTERNAL_UPSTREAM": "INHERIT"})

    restored = _restrictions(ca, domain, group)
    assert restored["EXTERNAL_UPSTREAM"]["mode"] == "INHERIT", (
        f"after putting the mode back the group reports "
        f"{restored['EXTERNAL_UPSTREAM']['mode']!r}, expected INHERIT"
    )
    assert restored["EXTERNAL_UPSTREAM"]["inheritedFrom"]["pattern"] == "/*", (
        f"the restored restriction inherits from "
        f"{restored['EXTERNAL_UPSTREAM'].get('inheritedFrom')!r}, expected the root group '/*'"
    )
    refusal = _error(lambda: _allowed(ca, domain, group, "EXTERNAL_UPSTREAM"))
    assert refusal == expected, (
        f"listing allowed repositories after the mode went back to INHERIT returned {refusal!r}, "
        f"expected the same {expected!r} as before it was ever set"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
