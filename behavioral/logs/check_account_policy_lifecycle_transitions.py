"""account-policy-lifecycle-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-policy-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """PutAccountPolicy creates an account-level policy visible via
    DescribeAccountPolicies; DeleteAccountPolicy removes it and it no longer appears."""
    logs = ctx.client("logs")
    policy_name = ctx.unique_name("sim2real-acctpol-")
    policy_doc = json.dumps({"Fields": ["sim2real_marker_field"]})

    logs.put_account_policy(
        policyName=policy_name, policyDocument=policy_doc, policyType="FIELD_INDEX_POLICY"
    )
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: logs.delete_account_policy(policyName=policy_name, policyType="FIELD_INDEX_POLICY")
        )
    )

    found = _poll_until(
        lambda: _lookup_account_policy(logs, policy_name),
        lambda p: p is not None,
        timeout_s=30.0,
    )
    stored = json.loads(found["policyDocument"])
    assert stored["Fields"] == ["sim2real_marker_field"], (
        f"expected round-tripped policyDocument Fields to be ['sim2real_marker_field'], "
        f"got {stored.get('Fields')!r}"
    )

    logs.delete_account_policy(policyName=policy_name, policyType="FIELD_INDEX_POLICY")
    _poll_until(
        lambda: _lookup_account_policy(logs, policy_name),
        lambda p: p is None,
        timeout_s=30.0,
    )

    # The delete's effect is already proven absent above; also prove the dead id is now
    # unusable, not just invisible: a mutation on the deleted id must also fail.
    code, message = _error(
        lambda: logs.delete_account_policy(policyName=policy_name, policyType="FIELD_INDEX_POLICY")
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted account policy, got {code!r}"
    )
    expected_message = "Specified resource does not exist!"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )


def _error(fn):
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


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _lookup_account_policy(logs_client, policy_name: str) -> dict | None:
    try:
        resp = logs_client.describe_account_policies(
            policyType="FIELD_INDEX_POLICY", policyName=policy_name
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise
    policies = resp.get("accountPolicies", [])
    for p in policies:
        if p.get("policyName") == policy_name:
            return p
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
