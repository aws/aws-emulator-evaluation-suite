"""repository-policy-revision-guards-concurrent-writes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "repository-policy-revision-guards-concurrent-writes"
GROUP = 'domain-policy-rejected'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        "the stale-revision write SUCCEEDED where real AWS rejects it — no error code to compare"
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


def _policy(sid, action):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Sid": sid, "Effect": "Deny", "Principal": "*",
                       "Action": action, "Resource": "*"}],
    })


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A domain-policy write carrying a stale policyRevision is refused with ConflictException and leaves
    the second writer's document; the write with the current revision succeeds and moves the revision."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))

    code, message = _error(lambda: ca.get_domain_permissions_policy(domain=domain))
    assert code == "ResourceNotFoundException", (
        f"a domain with no policy answered {code!r} to a policy read, expected "
        f"ResourceNotFoundException"
    )
    assert message == "No policy found for (domain): (%s)" % domain, (
        f"the no-policy read said {message!r}, expected it to name the domain"
    )

    first_document = _policy("sim2realFirst", "codeartifact:ListPackages")
    first = ca.put_domain_permissions_policy(
        domain=domain, policyDocument=first_document)["policy"]
    ctx.on_cleanup(lambda: ca.delete_domain_permissions_policy(domain=domain))
    stale_revision = first["revision"]

    second_document = _policy("sim2realSecond", "codeartifact:ListPackageVersions")
    second = ca.put_domain_permissions_policy(
        domain=domain, policyRevision=stale_revision, policyDocument=second_document)["policy"]
    assert second["revision"] != stale_revision, (
        f"the second write reused revision {stale_revision!r}; every accepted write must mint a "
        f"new one or the lock cannot detect anything"
    )

    third_document = _policy("sim2realThird", "codeartifact:DescribePackage")
    code, message = _error(lambda: ca.put_domain_permissions_policy(
        domain=domain, policyRevision=stale_revision, policyDocument=third_document))
    assert code == "ConflictException", (
        f"a write carrying the superseded revision returned {code!r}, expected ConflictException"
    )
    assert message == "Provided policy version conflicts with the server", (
        f"the refusal said {message!r}, expected it to name the version conflict"
    )

    stored = ca.get_domain_permissions_policy(domain=domain)["policy"]
    assert json.loads(stored["document"]) == json.loads(second_document), (
        f"the refused write still changed the document to {stored['document']!r}; the second "
        f"writer's policy must survive"
    )
    assert stored["revision"] == second["revision"], (
        f"the refused write moved the revision to {stored['revision']!r}, expected "
        f"{second['revision']!r}"
    )

    third = ca.put_domain_permissions_policy(
        domain=domain, policyRevision=second["revision"],
        policyDocument=third_document)["policy"]
    assert json.loads(third["document"]) == json.loads(third_document), (
        f"the positive control (same document, current revision) stored "
        f"{third['document']!r}"
    )
    assert third["revision"] not in (stale_revision, second["revision"]), (
        f"the control's revision {third['revision']!r} repeats an earlier one"
    )

    removed = ca.delete_domain_permissions_policy(domain=domain)["policy"]
    assert removed["revision"] == third["revision"], (
        f"the delete returned revision {removed.get('revision')!r}, expected the policy it "
        f"removed, {third['revision']!r}"
    )

    code, message = _error(lambda: ca.get_domain_permissions_policy(domain=domain))
    assert code == "ResourceNotFoundException", (
        f"an independent read after the delete returned {code!r}, expected "
        f"ResourceNotFoundException — the policy must actually be gone, not just reported gone"
    )
    assert message == "No policy found for (domain): (%s)" % domain, (
        f"the post-delete read said {message!r}, expected it to name the domain, matching the "
        f"no-policy read at the start of this check"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
