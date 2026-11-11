"""package-group-allowed-repository-update-without-mode-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-group-allowed-repository-update-without-mode-rejected"
GROUP = 'package-groups-rejected'
SERVICES = ['codeartifact']


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


def _restriction(ca, domain, pattern, kind):
    return ca.describe_package_group(
        domain=domain,
        packageGroup=pattern)["packageGroup"]["originConfiguration"]["restrictions"][kind]


def _allowed(ca, domain, pattern, kind):
    out = []
    for page in ca.get_paginator("list_allowed_repositories_for_group").paginate(
            domain=domain, packageGroup=pattern, originRestrictionType=kind):
        out.extend(page["allowedRepositories"])
    return sorted(out)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Adding an allowed repository while switching the mode to INHERIT is refused and leaves the list
    untouched; the same repository edit with the mode left alone succeeds.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    group = "/generic/sim2real-scope/*"
    edit = [{"repositoryName": repo, "originRestrictionType": "EXTERNAL_UPSTREAM"}]

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(
        domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))
    ca.create_package_group(
        domain=domain, packageGroup=group, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_package_group(domain=domain, packageGroup=group))

    refusal = _error(lambda: ca.update_package_group_origin_configuration(
        domain=domain, packageGroup=group,
        restrictions={"EXTERNAL_UPSTREAM": "INHERIT"}, addAllowedRepositories=edit))
    expected = (
        "ValidationException",
        "Resulting mode is not ALLOW_SPECIFIC_REPOSITORIES for [EXTERNAL_UPSTREAM]. Cannot add or "
        "remove allowed-repositories.",
    )
    assert refusal == expected, (
        f"adding an allowed repository while setting the mode to INHERIT returned {refusal!r}, "
        f"expected {expected!r}: the message names the RESULTING mode, which is what makes this a "
        f"cross-field rule rather than an enum check"
    )
    after = _restriction(ca, domain, group, "EXTERNAL_UPSTREAM")
    assert after["mode"] == "INHERIT" and "repositoriesCount" not in after, (
        f"the refused request still changed the restriction to {after!r}; a rejection must leave "
        f"the group inheriting with no repository list at all"
    )

    ca.update_package_group_origin_configuration(
        domain=domain, packageGroup=group,
        restrictions={"EXTERNAL_UPSTREAM": "ALLOW_SPECIFIC_REPOSITORIES"},
        addAllowedRepositories=edit)
    assert _allowed(ca, domain, group, "EXTERNAL_UPSTREAM") == [repo], (
        f"the positive control (the same repository edit with a compatible mode) left the allowed "
        f"list as {_allowed(ca, domain, group, 'EXTERNAL_UPSTREAM')!r}, expected [{repo!r}]"
    )

    refusal = _error(lambda: ca.update_package_group_origin_configuration(
        domain=domain, packageGroup=group,
        restrictions={"EXTERNAL_UPSTREAM": "BLOCK"}, removeAllowedRepositories=edit))
    expected = (
        "ValidationException",
        "Resulting mode is not ALLOW_SPECIFIC_REPOSITORIES for [EXTERNAL_UPSTREAM]. Cannot add or "
        "remove allowed-repositories.",
    )
    assert refusal == expected, (
        f"removing an allowed repository while setting the mode to BLOCK returned {refusal!r}, "
        f"expected {expected!r} — the rule is about the resulting mode, either direction"
    )
    assert _allowed(ca, domain, group, "EXTERNAL_UPSTREAM") == [repo], (
        f"the refused removal still emptied the allowed list: "
        f"{_allowed(ca, domain, group, 'EXTERNAL_UPSTREAM')!r}"
    )

    ca.update_package_group_origin_configuration(
        domain=domain, packageGroup=group, removeAllowedRepositories=edit)
    ca.update_package_group_origin_configuration(
        domain=domain, packageGroup=group, restrictions={"EXTERNAL_UPSTREAM": "INHERIT"})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
