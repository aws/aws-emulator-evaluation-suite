"""put-repository-permissions-policy-concurrent-writers-conflict."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-repository-permissions-policy-concurrent-writers-conflict"
GROUP = "concurrency"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two racing PutRepositoryPermissionsPolicy writers: the second writer, using a
    revision that was already superseded by another writer, is rejected with
    ConflictException and does not clobber the winning writer's document."""
    ca = ctx.client("codeartifact")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(
        domain=domain, repository=repository, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    def policy_doc(sid: str) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": sid,
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "codeartifact:GetRepositoryPermissionsPolicy",
                        "Resource": "*",
                    }
                ],
            }
        )

    # Initial write establishes revision1.
    resp1 = ca.put_repository_permissions_policy(
        domain=domain, repository=repository, policyDocument=policy_doc("RevisionOne")
    )
    revision1 = resp1["policy"]["revision"]

    # A racing writer reads revision1 (simulated by capturing it above), then a
    # DIFFERENT writer wins the race and updates the policy first.
    resp2 = ca.put_repository_permissions_policy(
        domain=domain, repository=repository, policyDocument=policy_doc("RevisionTwoWinner")
    )
    revision2 = resp2["policy"]["revision"]
    assert revision2 != revision1, (
        f"the second writer's write reused revision {revision1!r}; every accepted write must "
        f"mint a new revision or a stale-revision write could never be detected"
    )

    # The losing racer, still holding stale revision1, now tries to write.
    code, message = _error(
        lambda: ca.put_repository_permissions_policy(
            domain=domain,
            repository=repository,
            policyDocument=policy_doc("RevisionThreeLoser"),
            policyRevision=revision1,
        )
    )
    assert code == "ConflictException", (
        f"a write carrying the superseded revision {revision1!r} returned {code!r}, expected "
        f"ConflictException"
    )
    assert message == "Provided policy version conflicts with the server", (
        f"the stale-revision ConflictException said {message!r}, expected AWS's exact "
        f"'Provided policy version conflicts with the server'"
    )

    # Effect absent: the winner's document is untouched.
    current = ca.get_repository_permissions_policy(domain=domain, repository=repository)["policy"]
    assert current["revision"] == revision2, (
        f"the rejected write still moved the revision to {current['revision']!r}, expected the "
        f"winner's {revision2!r} to survive"
    )
    current_sid = json.loads(current["document"])["Statement"][0]["Sid"]
    assert current_sid == "RevisionTwoWinner", (
        f"the stored document's Sid is {current_sid!r}, expected the winner's "
        f"'RevisionTwoWinner' — the rejected write must not have touched it"
    )

    # Positive control: a write using the correct current revision succeeds.
    resp3 = ca.put_repository_permissions_policy(
        domain=domain,
        repository=repository,
        policyDocument=policy_doc("RevisionThreeCorrect"),
        policyRevision=revision2,
    )
    assert resp3["policy"]["revision"] != revision2, (
        f"the correctly-versioned write did not advance the revision past {revision2!r}"
    )
    final = ca.get_repository_permissions_policy(domain=domain, repository=repository)["policy"]
    final_sid = json.loads(final["document"])["Statement"][0]["Sid"]
    assert final_sid == "RevisionThreeCorrect", (
        f"the correctly-versioned write did not take: stored Sid is {final_sid!r}, expected "
        f"'RevisionThreeCorrect'"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(
        "the stale-revision write SUCCEEDED where real AWS rejects it — no error code to compare"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
