"""op-contract-getContextKeysForCustomPolicy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-getContextKeysForCustomPolicy"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetContextKeysForCustomPolicy returns every context key the policies
    reference in Condition blocks and resource variables, and fails with
    InvalidInput and its exact message for invalid policy JSON."""
    iam = ctx.client("iam")

    policy_one = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "dynamodb:*",
            "Resource": "arn:aws:dynamodb:us-east-2:123456789012:table/${aws:username}",
            "Condition": {"DateGreaterThan": {"aws:CurrentTime": "2015-08-16T12:00:00Z"}},
        },
    }
    policy_two = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        },
    }

    resp = iam.get_context_keys_for_custom_policy(
        PolicyInputList=[json.dumps(policy_one), json.dumps(policy_two)]
    )
    keys = set(resp["ContextKeyNames"])
    expected = {"aws:username", "aws:CurrentTime", "aws:MultiFactorAuthPresent"}
    assert expected <= keys, f"missing context keys: {expected - keys}, got {keys}"

    malformed = "{this is not valid json"
    code, message = _error(lambda: iam.get_context_keys_for_custom_policy(PolicyInputList=[malformed]))
    assert code == "InvalidInput", f"expected InvalidInput, got {code!r}"
    expected = "Policy input list item 1 has invalid content"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
