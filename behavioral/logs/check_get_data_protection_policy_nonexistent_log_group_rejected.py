"""get-data-protection-policy-nonexistent-log-group-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "get-data-protection-policy-nonexistent-log-group-rejected"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDataProtectionPolicy against a log group that was never created is rejected with
    ResourceNotFoundException -- distinct from the (empty-but-successful) case of an existing log
    group with no policy attached, which a positive control in this same file exercises."""
    logs = ctx.client("logs")

    valid_group = ctx.unique_name("sim2real-dppneg-lg-")
    logs.create_log_group(logGroupName=valid_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=valid_group))

    policy_doc = json.dumps(
        {
            "Name": "sim2real-neg-policy",
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "audit-policy",
                    "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                    "Operation": {"Audit": {"FindingsDestination": {}}},
                },
                {
                    "Sid": "redact-policy",
                    "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                    "Operation": {"Deidentify": {"MaskConfig": {}}},
                },
            ],
        }
    )
    logs.put_data_protection_policy(logGroupIdentifier=valid_group, policyDocument=policy_doc)

    # Positive control: fetching the policy for the real, existing log group succeeds.
    resp = logs.get_data_protection_policy(logGroupIdentifier=valid_group)
    got_doc = json.loads(resp["policyDocument"])
    want_doc = json.loads(policy_doc)
    assert got_doc == want_doc, f"policy round-trip mismatch: expected {want_doc!r}, got {got_doc!r}"

    # Negative: fetching for a log group that was never created is rejected.
    missing_group = ctx.unique_name("sim2real-dppneg-missing-")
    code, message = _error(lambda: logs.get_data_protection_policy(logGroupIdentifier=missing_group))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a log group that was never created, got {code!r}"
    )
    expected_message = f"Log group '{missing_group}' for owner '{ctx.account}' cannot be found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the nonexistent log group still does not exist and has no policy of its own
    # (there was never a resource to mutate; DescribeLogGroups confirms it was never created).
    described = logs.describe_log_groups(logGroupNamePrefix=missing_group)["logGroups"]
    assert described == [], f"expected no log groups matching {missing_group!r}, found {described!r}"


def _error(fn: Callable[[], Any]):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
