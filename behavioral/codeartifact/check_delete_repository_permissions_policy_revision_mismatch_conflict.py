"""delete-repository-permissions-policy-revision-mismatch-conflict."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-repository-permissions-policy-revision-mismatch-conflict"
GROUP = "concurrency"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRepositoryPermissionsPolicy is rejected with ConflictException when the
    supplied policyRevision does not match the current policy revision, and the
    policy remains attached; deleting with the correct revision then succeeds."""
    ca = ctx.client("codeartifact")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowRootRead",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "codeartifact:GetRepositoryPermissionsPolicy",
                    "Resource": "*",
                }
            ],
        }
    )
    put_resp = ca.put_repository_permissions_policy(
        domain=domain, repository=repository, policyDocument=policy_doc
    )
    real_revision = put_resp["policy"]["revision"]

    bogus_revision = real_revision[::-1] + "x"
    refusal = _error(
        lambda: ca.delete_repository_permissions_policy(
            domain=domain, repository=repository, policyRevision=bogus_revision
        )
    )
    expected = ("ConflictException", "Provided policy version conflicts with the server")
    assert refusal == expected, (
        f"expected {expected!r} deleting with mismatched revision {bogus_revision!r} "
        f"(real revision {real_revision!r}), got {refusal!r}"
    )

    still_there = ca.get_repository_permissions_policy(domain=domain, repository=repository)["policy"]
    assert still_there["revision"] == real_revision, (
        f"expected the policy revision to remain {real_revision!r} after the rejected delete, "
        f"got {still_there['revision']!r}"
    )
    sid = json.loads(still_there["document"])["Statement"][0]["Sid"]
    assert sid == "AllowRootRead", (
        f"expected the untouched policy document to still carry Sid 'AllowRootRead', got {sid!r}"
    )

    # Positive control: delete with the correct revision succeeds.
    ca.delete_repository_permissions_policy(
        domain=domain, repository=repository, policyRevision=real_revision
    )
    after = _error(
        lambda: ca.get_repository_permissions_policy(domain=domain, repository=repository)
    )
    expected_after = (
        "ResourceNotFoundException",
        f"No policy found for (domain, repo): ({domain}, {repository})",
    )
    assert after == expected_after, (
        f"expected {expected_after!r} reading the policy after the correctly-versioned "
        f"delete, got {after!r}"
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
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
