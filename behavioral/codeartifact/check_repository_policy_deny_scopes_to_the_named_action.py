"""repository-policy-deny-scopes-to-the-named-action."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "repository-policy-deny-scopes-to-the-named-action"
GROUP = 'repository-policy-denied'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        "the call SUCCEEDED where the repository policy denies it — there is no error code"
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


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A repository policy's explicit Deny blocks exactly the named action with an AccessDeniedException
    from a resource-based policy; neighbouring actions still succeed, and deleting the policy restores
    the denied action.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-policy-scoped"
    content = b"policy-scoped-payload\n"
    scope = dict(format="generic", namespace="sim2real", package=package)
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "sim2realDenyDescribePackageVersion",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "codeartifact:DescribePackageVersion",
            "Resource": "*",
        }],
    }

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))
    ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", assetContent=content,
        assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(), **scope)
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))

    assert ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope
    )["packageVersion"]["status"] == "Published", (
        "the version must be readable BEFORE the policy, or the denial below proves nothing"
    )

    put = ca.put_repository_permissions_policy(
        domain=domain, repository=repo, policyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: ca.delete_repository_permissions_policy(
        domain=domain, repository=repo))
    assert json.loads(put["policy"]["document"]) == policy, (
        f"the stored policy is {put['policy']['document']!r}, expected the document that was put"
    )

    code, message = _error(lambda: ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope))
    assert code == "AccessDeniedException", (
        f"the denied action returned {code!r}, expected AccessDeniedException"
    )
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    package_arn = (
        f"arn:aws:codeartifact:{ctx.region}:{ctx.account}:package/{domain}/{repo}/generic/"
        f"sim2real/{package}"
    )
    denied = (
        f"User: {caller} is not authorized to perform: codeartifact:DescribePackageVersion on "
        f"resource: {package_arn} with an explicit deny in a resource-based policy"
    )
    assert message == denied, (
        f"the denial said {message!r}; expected {denied!r}, which attributes the decision to "
        f"the resource-based policy and shows the document was evaluated"
    )

    assert ca.describe_repository(
        domain=domain, repository=repo)["repository"]["name"] == repo, (
        "DescribeRepository was denied too; the Deny names only DescribePackageVersion"
    )
    listed = []
    for page in ca.get_paginator("list_packages").paginate(domain=domain, repository=repo):
        listed.extend(page["packages"])
    assert [p["package"] for p in listed] == [package], (
        f"ListPackages on the same repository returned {[p['package'] for p in listed]!r}; it is "
        f"outside the Deny and must still answer"
    )

    ca.delete_repository_permissions_policy(domain=domain, repository=repo)
    assert ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope
    )["packageVersion"]["status"] == "Published", (
        "deleting the policy did not restore the denied action"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
