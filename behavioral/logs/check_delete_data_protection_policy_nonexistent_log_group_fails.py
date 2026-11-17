"""delete-data-protection-policy-nonexistent-log-group-fails."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-data-protection-policy-nonexistent-log-group-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDataProtectionPolicy on a log group that was never created raises
    ResourceNotFoundException with its exact message, and leaves no policy behind
    for an existing group that never had one deleted."""
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-ddpneg-lg-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    policy_doc = json.dumps(
        {
            "Name": "sim2real-ddpneg-policy",
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "auditStatement",
                    "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                    "Operation": {"Audit": {"FindingsDestination": {}}},
                },
                {
                    "Sid": "deidentifyStatement",
                    "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                    "Operation": {"Deidentify": {"MaskConfig": {}}},
                },
            ],
        }
    )
    logs.put_data_protection_policy(logGroupIdentifier=group, policyDocument=policy_doc)

    # Positive control: deleting the policy of a real, existing log group succeeds, and the
    # group is left with no policy document (GetDataProtectionPolicy still succeeds, empty).
    logs.delete_data_protection_policy(logGroupIdentifier=group)
    after_delete = logs.get_data_protection_policy(logGroupIdentifier=group)
    assert "policyDocument" not in after_delete, (
        f"expected no policyDocument after DeleteDataProtectionPolicy, got {after_delete!r}"
    )

    # Negative: deleting a policy for a log group that was never created is rejected.
    missing_group = ctx.unique_name("sim2real-ddpneg-missing-")
    code, message = _error(
        lambda: logs.delete_data_protection_policy(logGroupIdentifier=missing_group)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting a policy on a log group that never "
        f"existed, got {code!r} {message!r}"
    )
    expected_message = f"Log group '{missing_group}' for owner '{ctx.account}' cannot be found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the log group named by the rejected call was never created.
    described = logs.describe_log_groups(logGroupNamePrefix=missing_group)["logGroups"]
    assert described == [], f"expected no log groups matching {missing_group!r}, found {described!r}"


def _error(fn: Callable[[], Any]):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
