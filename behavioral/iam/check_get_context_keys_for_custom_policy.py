"""get-context-keys-for-custom-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-context-keys-for-custom-policy"
GROUP = 'policy_simulation'
SERVICES = ['iam']

# A tiny policy whose Condition block references a single, unambiguous condition context key, so
# the returned ContextKeyNames set must come from the ACTUAL policy content, not a fixed response.
POLICY_WITH_CONTEXT_KEY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            }
        ],
    }
)


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetContextKeysForCustomPolicy returns exactly the condition key a policy references
    (aws:SourceIp) and fails with InvalidInput and its exact message when the list holds invalid
    policy JSON."""
    iam = ctx.client("iam")
    resp = iam.get_context_keys_for_custom_policy(PolicyInputList=[POLICY_WITH_CONTEXT_KEY])
    assert set(resp["ContextKeyNames"]) == {"aws:SourceIp"}, (
        f"expected exactly {{'aws:SourceIp'}} extracted from the policy, got {resp['ContextKeyNames']}"
    )

    # GetContextKeysForCustomPolicy models exactly one error shape (InvalidInputException, wire
    # code "InvalidInput") -- MalformedPolicyDocument belongs to other IAM operations, not this one.
    code, message = _error(
        lambda: iam.get_context_keys_for_custom_policy(PolicyInputList=["{not valid json"])
    )
    assert code == "InvalidInput", f"expected InvalidInput for invalid JSON, got {code}"
    expected = "Policy input list item 1 has invalid content"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
