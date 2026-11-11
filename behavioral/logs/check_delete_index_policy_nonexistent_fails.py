"""delete-index-policy-nonexistent-fails."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-index-policy-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIndexPolicy removes a log group's real index policy, and on a group with no index policy raises
    ResourceNotFoundException "Specified resource does not exist!"."""
    logs = ctx.client("logs")

    # Positive control: DeleteIndexPolicy actually removes a policy that exists, on a
    # different log group than the one under test.
    control_group = ctx.unique_name("sim2real-behav-lg-ctrl-")
    logs.create_log_group(logGroupName=control_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=control_group))
    logs.put_index_policy(
        logGroupIdentifier=control_group, policyDocument=json.dumps({"Fields": ["RequestId"]})
    )
    control_policies = logs.describe_index_policies(logGroupIdentifiers=[control_group])[
        "indexPolicies"
    ]
    assert len(control_policies) == 1, f"expected the control policy to be visible, got {control_policies}"

    logs.delete_index_policy(logGroupIdentifier=control_group)
    control_after = logs.describe_index_policies(logGroupIdentifiers=[control_group])["indexPolicies"]
    assert control_after == [], f"expected control policy gone after delete, got {control_after}"

    # Subject: a log group that never had an index policy configured at all.
    group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    # Sanity: there really is no index policy configured on this fresh log group.
    subject_policies = logs.describe_index_policies(logGroupIdentifiers=[group])["indexPolicies"]
    assert subject_policies == [], f"expected no index policy on a fresh log group, got {subject_policies}"

    code, message = _error(lambda: logs.delete_index_policy(logGroupIdentifier=group))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting a non-existent index policy, got {code}"
    )
    assert message == "Specified resource does not exist!", (
        f"unexpected message deleting a non-existent index policy: {message!r}"
    )


def _error(fn):
    """The (code, message) fn() raised; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
