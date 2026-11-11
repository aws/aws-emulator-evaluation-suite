"""put-domain-permissions-policy-stale-revision-conflict."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-domain-permissions-policy-stale-revision-conflict"
GROUP = "concurrency"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDomainPermissionsPolicy with a stale policyRevision is rejected with
    ConflictException instead of silently overwriting a concurrent update, and the
    concurrent writer's version is left intact."""
    ca = ctx.client("codeartifact")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain = ctx.unique_name("sim2real-ca-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    def policy_doc(sid: str) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": sid,
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "codeartifact:GetDomainPermissionsPolicy",
                        "Resource": "*",
                    }
                ],
            }
        )

    # Writer A puts the first version of the policy.
    resp1 = ca.put_domain_permissions_policy(domain=domain, policyDocument=policy_doc("RevisionOne"))
    revision1 = resp1["policy"]["revision"]

    # Writer B (a concurrent update) overwrites it without knowing about a stale reader.
    resp2 = ca.put_domain_permissions_policy(domain=domain, policyDocument=policy_doc("RevisionTwo"))
    revision2 = resp2["policy"]["revision"]
    assert revision2 != revision1, (
        f"writer B's accepted write reused revision {revision1!r}; every accepted write must "
        f"mint a new one or the lock cannot detect anything"
    )

    # Writer A, still holding the stale revision1, now tries to write -- must be rejected.
    code, message = _error(
        lambda: ca.put_domain_permissions_policy(
            domain=domain, policyDocument=policy_doc("RevisionThreeStale"), policyRevision=revision1
        )
    )
    assert code == "ConflictException", (
        f"a write carrying the superseded revision {revision1!r} returned {code!r}, expected "
        f"ConflictException"
    )
    assert message == "Provided policy version conflicts with the server", (
        f"the refusal said {message!r}, expected it to name the version conflict"
    )

    # The effect of the stale write must be absent: the policy must still be Writer B's.
    current = ca.get_domain_permissions_policy(domain=domain)["policy"]
    assert current["revision"] == revision2, (
        f"the refused write moved the revision to {current['revision']!r}, expected it to stay "
        f"at writer B's {revision2!r}"
    )
    assert json.loads(current["document"])["Statement"][0]["Sid"] == "RevisionTwo", (
        f"the refused write changed the stored document to {current['document']!r}; writer B's "
        f"policy must survive"
    )

    # Positive control: a write using the CORRECT current revision succeeds.
    resp3 = ca.put_domain_permissions_policy(
        domain=domain, policyDocument=policy_doc("RevisionThreeCorrect"), policyRevision=revision2
    )
    assert resp3["policy"]["revision"] != revision2, (
        f"the accepted write carrying the current revision {revision2!r} reused it instead of "
        f"minting a new one"
    )
    final = ca.get_domain_permissions_policy(domain=domain)["policy"]
    assert json.loads(final["document"])["Statement"][0]["Sid"] == "RevisionThreeCorrect", (
        f"the write carrying the correct current revision did not take effect: "
        f"{final['document']!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING a stale-revision write real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        response = getattr(exc, "response", None)
        if response is None:
            raise
        error = response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
