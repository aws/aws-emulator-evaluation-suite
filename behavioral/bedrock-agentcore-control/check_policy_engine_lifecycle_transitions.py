"""policy-engine-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-engine-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PolicyEngine create->CREATING->ACTIVE, UpdatePolicyEngine persists a
    changed field and returns to ACTIVE, and DeletePolicyEngine leaves the
    engine unavailable (GetPolicyEngine returns ResourceNotFoundException)."""
    bac = ctx.client("bedrock-agentcore-control")
    name = _safe_name(ctx, "sim2realpe")

    create_resp = bac.create_policy_engine(
        name=name, tags={"sim2real": "policy-engine-lifecycle-transitions"}
    )
    pe_id = create_resp["policyEngineId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: bac.delete_policy_engine(policyEngineId=pe_id)))

    pe = _poll_until(
        lambda: bac.get_policy_engine(policyEngineId=pe_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )
    assert pe["status"] == "ACTIVE", f"unexpected terminal status {pe['status']!r}"

    update_resp = bac.update_policy_engine(
        policyEngineId=pe_id, description={"optionalValue": "sim2real-updated"}
    )
    assert update_resp["description"] == "sim2real-updated", (
        f"expected updated description 'sim2real-updated', got {update_resp['description']!r}"
    )
    pe2 = _poll_until(
        lambda: bac.get_policy_engine(policyEngineId=pe_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
    )
    assert pe2["status"] == "ACTIVE", f"unexpected terminal status {pe2['status']!r}"

    bac.delete_policy_engine(policyEngineId=pe_id)
    code, message = _error(
        lambda: bac.get_policy_engine(policyEngineId=pe_id),
        until_code="ResourceNotFoundException",
        timeout_s=90.0,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Policy engine with ID {pe_id} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    mutate_code, mutate_message = _error(
        lambda: bac.update_policy_engine(
            policyEngineId=pe_id, description={"optionalValue": "sim2real-post-delete"}
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdatePolicyEngine on a deleted engine to fail with "
        f"ResourceNotFoundException, got {mutate_code!r}"
    )
    expected = f"Policy engine with ID {pe_id} not found"
    assert mutate_message == expected, f"expected message {expected!r}, got {mutate_message!r}"


def _error(fn, *, until_code=None, timeout_s=0.0, interval_s=3.0):
    """Return (code, message) of the ClientError fn() raises. With until_code, retry while fn()
    succeeds or raises another code, for up to timeout_s. A call that never fails raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            error = err.response["Error"]
            if until_code is None or error["Code"] == until_code or time.monotonic() >= deadline:
                return error["Code"], error.get("Message", "")
        else:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"expected a ClientError, but the call succeeded and returned {result!r}"
                )
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _safe_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c for c in raw if c.isalnum() or c == "_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _safe_delete(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
