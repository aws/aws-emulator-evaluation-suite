"""create-repository-duplicate-does-not-clobber."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-repository-duplicate-does-not-clobber"
GROUP = 'repository-create-rejected'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        "the duplicate create SUCCEEDED where real AWS rejects it — no error code to compare"
    )


def _delete_repo(ca, domain, repo, deadline=90.0):
    """DeleteRepository, retrying the upstream-reference conflict.

    A repository still named as an upstream cannot be deleted, and the reference outlives the
    downstream repository's own delete by tens of seconds (measured: a single-shot cleanup here
    stranded the upstream AND the domain holding it).
    """
    end = time.time() + deadline
    while True:
        try:
            ca.delete_repository(domain=domain, repository=repo)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


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


def _repositories(ca, domain):
    out = []
    for page in ca.get_paginator("list_repositories_in_domain").paginate(domain=domain):
        out.extend(r["name"] for r in page["repositories"])
    return sorted(out)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A duplicate CreateRepository fails with ConflictException naming the repository and domain
    and leaves the original description, upstreams and createdTime intact; the name is free again
    after deletion and is unique per domain, not per account."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    other_domain = ctx.unique_name("sim2real-behav-ca-alt-")
    upstream = ctx.unique_name("sim2real-behav-ca-up-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")

    ca.create_domain(domain=domain)
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=upstream)
    ctx.on_cleanup(lambda: _delete_repo(ca, domain, upstream))

    original = ca.create_repository(
        domain=domain, repository=repo, description="sim2real original description",
        upstreams=[{"repositoryName": upstream}])["repository"]
    ctx.on_cleanup(lambda: _delete_repo(ca, domain, repo))
    ctx.on_cleanup(lambda: ca.update_repository(domain=domain, repository=repo, upstreams=[]))

    code, message = _error(lambda: ca.create_repository(
        domain=domain, repository=repo, description="sim2real CLOBBERED description"))
    assert code == "ConflictException", (
        f"the duplicate create returned {code!r}, expected ConflictException"
    )
    assert message == "Repository %s already exists in domain %s." % (repo, domain), (
        f"the refusal said {message!r}; expected it to name both the repository and the domain"
    )

    survived = ca.describe_repository(domain=domain, repository=repo)["repository"]
    assert survived["description"] == "sim2real original description", (
        f"the refused create rewrote the description to {survived['description']!r}"
    )
    assert [u["repositoryName"] for u in survived["upstreams"]] == [upstream], (
        f"the refused create left upstreams {survived['upstreams']!r}, expected the original "
        f"[{upstream!r}] — a create that carried no upstreams must not clear them"
    )
    assert survived["createdTime"] == original["createdTime"], (
        f"the refused create moved createdTime from {original['createdTime']!r} to "
        f"{survived['createdTime']!r}"
    )
    assert _repositories(ca, domain) == sorted([repo, upstream]), (
        f"the domain holds {_repositories(ca, domain)!r}, expected exactly the two repositories — "
        f"the refused create must not have added a third"
    )

    # Restore leg: the conflict is about the NAME BEING TAKEN, not a permanent block — free it
    # by deleting the repository, then the identical call must now succeed.
    _delete_repo(ca, domain, repo)
    reborn = ca.create_repository(
        domain=domain, repository=repo, description="sim2real reborn after delete")["repository"]
    # No new on_cleanup here: the delete_repo cleanup registered above (for the original create)
    # closes over the same domain/repo strings and already covers this reborn repository too.
    reread = ca.describe_repository(domain=domain, repository=repo)["repository"]
    assert reread["description"] == "sim2real reborn after delete", (
        f"after freeing the name, the identical create should have landed, but an independent read "
        f"shows description {reread['description']!r}"
    )
    assert reread["arn"] == reborn["arn"], (
        f"the independent read's arn {reread['arn']!r} disagrees with the create response's "
        f"{reborn['arn']!r}"
    )

    ca.create_domain(domain=other_domain)
    ctx.on_cleanup(lambda: _delete_domain(ca, other_domain))
    ca.create_repository(
        domain=other_domain, repository=repo,
        description="sim2real same name, other domain")
    ctx.on_cleanup(lambda: ca.delete_repository(domain=other_domain, repository=repo))
    twin = ca.describe_repository(domain=other_domain, repository=repo)["repository"]
    assert twin["domainName"] == other_domain, (
        f"the positive control landed in domain {twin['domainName']!r}, expected {other_domain!r}"
    )
    assert twin["arn"] != reread["arn"], (
        f"both repositories report arn {twin['arn']!r}; a repository name is unique per DOMAIN, so "
        f"the two must be distinct resources"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
