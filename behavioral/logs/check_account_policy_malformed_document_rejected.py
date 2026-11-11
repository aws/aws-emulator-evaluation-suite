"""account-policy-malformed-document-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "account-policy-malformed-document-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """PutAccountPolicy with a field-index document whose "Fields" is not an array raises
    InvalidParameterException with its exact message and creates no policy, while a well-formed document
    is accepted."""
    logs = ctx.client("logs")

    # Positive control: prove PutAccountPolicy for FIELD_INDEX_POLICY works at all on this
    # wiring, so the rejection below can be attributed to the malformed "Fields" value
    # specifically and not to e.g. missing permissions or a blanket refusal.
    control_name = ctx.unique_name("sim2real-goodacctpol-")
    control_doc = {"Fields": ["sim2real_marker_field"]}
    ctx.on_cleanup(lambda: _safe_call(
        lambda: logs.delete_account_policy(policyName=control_name, policyType="FIELD_INDEX_POLICY")
    ))
    logs.put_account_policy(
        policyName=control_name,
        policyDocument=json.dumps(control_doc),
        policyType="FIELD_INDEX_POLICY",
    )
    control_resp = logs.describe_account_policies(
        policyType="FIELD_INDEX_POLICY", policyName=control_name
    )
    control_matches = [
        p for p in control_resp.get("accountPolicies", []) if p.get("policyName") == control_name
    ]
    assert control_matches, (
        f"positive control: expected account policy {control_name!r} to exist after a "
        f"well-formed PutAccountPolicy, found none in {control_resp.get('accountPolicies', [])!r}"
    )

    policy_name = ctx.unique_name("sim2real-badacctpol-")
    ctx.on_cleanup(lambda: _safe_call(
        lambda: logs.delete_account_policy(policyName=policy_name, policyType="FIELD_INDEX_POLICY")
    ))

    malformed_doc = '{"Fields": "not-an-array"}'
    code, message = _error(
        lambda: logs.put_account_policy(
            policyName=policy_name, policyDocument=malformed_doc, policyType="FIELD_INDEX_POLICY"
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected_message = "Policy document contains invalid JSON format."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # The rejected Put must not have left a partially-created policy behind: a lookup by
    # that name answers with an empty list.
    resp = logs.describe_account_policies(policyType="FIELD_INDEX_POLICY", policyName=policy_name)
    matches = [p for p in resp.get("accountPolicies", []) if p.get("policyName") == policy_name]
    assert not matches, (
        f"expected no account policy named {policy_name!r} after the rejected "
        f"PutAccountPolicy, found {matches!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() expecting a ClientError; return its (Code, Message). A success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_call(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
