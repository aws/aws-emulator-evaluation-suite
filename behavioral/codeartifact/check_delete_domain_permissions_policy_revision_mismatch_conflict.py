"""delete-domain-permissions-policy-revision-mismatch-conflict."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-domain-permissions-policy-revision-mismatch-conflict"
GROUP = "concurrency"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomainPermissionsPolicy is rejected with ConflictException when the
    supplied policyRevision does not match the current policy, leaving the policy
    in place; deleting with the correct revision then succeeds."""
    ca = ctx.client("codeartifact")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain = ctx.unique_name("sim2real-ca-")

    ca.create_domain(domain=domain)
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowRootRead",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "codeartifact:GetDomainPermissionsPolicy",
                    "Resource": "*",
                }
            ],
        }
    )
    put_resp = ca.put_domain_permissions_policy(domain=domain, policyDocument=policy_doc)
    real_revision = put_resp["policy"]["revision"]

    # Attempt delete with a revision string that does not match the current one.
    bogus_revision = real_revision[::-1] + "x"
    refusal = _error(
        lambda: ca.delete_domain_permissions_policy(domain=domain, policyRevision=bogus_revision)
    )
    expected = ("ConflictException", "Provided policy version conflicts with the server")
    assert refusal == expected, (
        f"expected {expected!r} for a stale policyRevision, got {refusal!r}"
    )

    # Effect absent: the policy must still exist, unchanged.
    still_there = ca.get_domain_permissions_policy(domain=domain)["policy"]
    assert still_there["revision"] == real_revision, (
        f"expected revision {real_revision!r} unchanged after the rejected delete, "
        f"got {still_there['revision']!r}"
    )
    sid = json.loads(still_there["document"])["Statement"][0]["Sid"]
    assert sid == "AllowRootRead", (
        f"expected policy document Sid 'AllowRootRead' unchanged, got {sid!r}"
    )

    # Restore: delete with the correct revision succeeds.
    ca.delete_domain_permissions_policy(domain=domain, policyRevision=real_revision)
    after = _error(lambda: ca.get_domain_permissions_policy(domain=domain))
    expected_after = ("ResourceNotFoundException", f"No policy found for (domain): ({domain})")
    assert after == expected_after, (
        f"expected {expected_after!r} reading a deleted policy, got {after!r}"
    )

    # DeleteDomainPermissionsPolicy is idempotent: re-deleting an already-absent
    # policy succeeds again (no ResourceNotFoundException) and reports no revision.
    redelete_policy = ca.delete_domain_permissions_policy(
        domain=domain, policyRevision=real_revision
    )["policy"]
    assert "revision" not in redelete_policy, (
        f"expected no revision on a delete of an already-absent policy, got {redelete_policy!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of a call that MUST be rejected; raises if it succeeds."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
