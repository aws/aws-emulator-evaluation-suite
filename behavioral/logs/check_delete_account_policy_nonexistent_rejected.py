"""delete-account-policy-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-account-policy-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]

# FIELD_INDEX_POLICY (unlike DATA_PROTECTION_POLICY) is not a strict one-per-account
# singleton, so creating and deleting one here for the positive control cannot collide
# with another check's account-wide DATA_PROTECTION_POLICY assumption.
_CONTROL_POLICY_TYPE = "FIELD_INDEX_POLICY"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """DeleteAccountPolicy removes a real FIELD_INDEX_POLICY, then raises ResourceNotFoundException with its
    exact message for it and for a never-created DATA_PROTECTION_POLICY name."""
    logs = ctx.client("logs")

    # Positive control: create a real account policy, confirm it independently, delete
    # it (must succeed), confirm the deletion independently, then delete the same
    # deleted policy again (must fail with the specific not-found code).
    real_name = ctx.unique_name("sim2real-acctpolicy-real-")
    logs.put_account_policy(
        policyName=real_name,
        policyDocument='{"Fields": ["sim2real_marker_field"]}',
        policyType=_CONTROL_POLICY_TYPE,
    )
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: logs.delete_account_policy(policyName=real_name, policyType=_CONTROL_POLICY_TYPE)
        )
    )

    visible = logs.describe_account_policies(
        policyType=_CONTROL_POLICY_TYPE, policyName=real_name
    ).get("accountPolicies", [])
    assert len(visible) == 1 and visible[0]["policyName"] == real_name, (
        f"expected the created account policy to be visible via DescribeAccountPolicies, got {visible!r}"
    )

    logs.delete_account_policy(policyName=real_name, policyType=_CONTROL_POLICY_TYPE)

    remaining = logs.describe_account_policies(
        policyType=_CONTROL_POLICY_TYPE, policyName=real_name
    ).get("accountPolicies", [])
    assert remaining == [], f"deleted account policy must not still be visible, got {remaining!r}"

    code, message = _error(
        lambda: logs.delete_account_policy(policyName=real_name, policyType=_CONTROL_POLICY_TYPE)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted policy, got {code}"
    )
    assert message == "Specified resource does not exist!", (
        f"unexpected message deleting an already-deleted {_CONTROL_POLICY_TYPE}: {message!r}"
    )

    # The check's namesake contract: a policyName/policyType combination that was NEVER
    # created is rejected the same way.
    bogus_name = ctx.unique_name("sim2real-nonexistent-acct-policy-")
    code, message = _error(
        lambda: logs.delete_account_policy(policyName=bogus_name, policyType="DATA_PROTECTION_POLICY")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # AWS's DATA_PROTECTION_POLICY path spells it "exists"; the FIELD_INDEX_POLICY path above
    # spells it "exist".
    assert message == "Specified resource does not exists!", (
        f"unexpected message deleting a never-created DATA_PROTECTION_POLICY: {message!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"expected DeleteAccountPolicy to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _swallow_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
