"""delete-nonexistent-account-policy-fails."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-nonexistent-account-policy-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]

_POLICY_TYPE = "FIELD_INDEX_POLICY"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """DeleteAccountPolicy for a never-created policy raises ResourceNotFoundException with its exact message;
    a real policy of the same type deletes and is unlisted, and deleting it again raises
    ResourceNotFoundException with its exact message.
    """
    logs = ctx.client("logs")
    missing_name = ctx.unique_name("sim2real-acctpolicy-missing-")
    real_name = ctx.unique_name("sim2real-acctpolicy-real-")

    error = _expect_error(
        lambda: logs.delete_account_policy(policyName=missing_name, policyType=_POLICY_TYPE)
    )
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error!r}"
    )
    expected_message = "Specified resource does not exist!"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # positive control: a policy that genuinely exists deletes successfully
    logs.put_account_policy(
        policyName=real_name,
        policyDocument=json.dumps({"Fields": ["sim2real_marker_field"]}),
        policyType=_POLICY_TYPE,
    )
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: logs.delete_account_policy(policyName=real_name, policyType=_POLICY_TYPE)
        )
    )

    logs.delete_account_policy(policyName=real_name, policyType=_POLICY_TYPE)

    # independent read confirms it is actually gone
    remaining = logs.describe_account_policies(
        policyType=_POLICY_TYPE, policyName=real_name
    ).get("accountPolicies", [])
    assert remaining == [], f"expected {real_name} gone after delete, still listed: {remaining}"

    # deleting the deleted policy again reproduces the same not-found error
    again = _expect_error(
        lambda: logs.delete_account_policy(policyName=real_name, policyType=_POLICY_TYPE)
    )
    assert again.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted policy, got {again!r}"
    )
    expected_again = "Specified resource does not exist!"
    assert again.get("Message") == expected_again, (
        f"expected message {expected_again!r}, got {again.get('Message')!r}"
    )


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
