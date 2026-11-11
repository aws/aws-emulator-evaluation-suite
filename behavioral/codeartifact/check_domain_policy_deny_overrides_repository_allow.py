"""domain-policy-deny-overrides-repository-allow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-policy-deny-overrides-repository-allow"
GROUP = 'domain-policy-denied'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"the call SUCCEEDED where the domain policy denies it and returned {result!r}"
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


def _packages(ca, domain, repo):
    out = []
    for page in ca.get_paginator("list_packages").paginate(domain=domain, repository=repo):
        out.extend(page["packages"])
    return out


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A domain policy Deny beats a repository policy Allow for ListPackages; the denial names the
    repository ARN, and removing only the domain policy restores the call.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    domain_deny = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "sim2realDomainDenyListPackages",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "codeartifact:ListPackages",
            "Resource": "*",
        }],
    }

    created = ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    # The domain's own `owner` is the account, so the policy principal never comes from a
    # GetCallerIdentity on the running identity.
    repo_allow = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "sim2realRepoAllowListPackages",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::%s:root" % created["domain"]["owner"]},
            "Action": "codeartifact:ListPackages",
            "Resource": "*",
        }],
    }
    ca.create_repository(domain=domain, repository=repo)
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    assert _packages(ca, domain, repo) == [], (
        "the repository must be listable BEFORE the policies, or the denial below proves nothing"
    )

    ca.put_repository_permissions_policy(
        domain=domain, repository=repo, policyDocument=json.dumps(repo_allow))
    ctx.on_cleanup(lambda: ca.delete_repository_permissions_policy(
        domain=domain, repository=repo))
    assert _packages(ca, domain, repo) == [], (
        "the repository-level Allow alone already broke the call, so the deny below would be "
        "attributable to the wrong document"
    )

    ca.put_domain_permissions_policy(domain=domain, policyDocument=json.dumps(domain_deny))
    ctx.on_cleanup(lambda: ca.delete_domain_permissions_policy(domain=domain))

    caller = ctx.client("sts").get_caller_identity()["Arn"]
    owner = created["domain"]["owner"]
    refusal = _error(lambda: _packages(ca, domain, repo))
    expected = (
        "AccessDeniedException",
        f"User: {caller} is not authorized to perform: codeartifact:ListPackages on resource: "
        f"arn:aws:codeartifact:{ctx.region}:{owner}:repository/{domain}/{repo} with an explicit "
        f"deny in a resource-based policy",
    )
    assert refusal == expected, (
        f"with a domain Deny and a repository Allow in force, ListPackages returned {refusal!r}, "
        f"expected {expected!r} — an explicit Deny at any level wins, it is attributed to a "
        f"resource-based policy, and it is reported against the REPOSITORY being acted on even "
        f"though the deny lives on the domain"
    )

    stored = ca.get_repository_permissions_policy(domain=domain, repository=repo)["policy"]
    assert json.loads(stored["document"]) == repo_allow, (
        f"the repository Allow changed to {stored['document']!r}; the domain deny must not rewrite "
        f"the repository's own document"
    )

    ca.delete_domain_permissions_policy(domain=domain)
    assert _packages(ca, domain, repo) == [], (
        "removing only the domain policy did not restore ListPackages, so the repository Allow was "
        "not what was carrying the call"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
