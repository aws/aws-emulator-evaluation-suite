"""op-managed-scaling-policy-ops-reject-unknown-cluster."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-managed-scaling-policy-ops-reject-unknown-cluster"
GROUP = 'overly-permissive'
SERVICES = ['emr']

THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")

UNKNOWN_CLUSTER_ID = "j-" + "Z" * 13

def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")

def _assert_rejections(cases: dict, expected: dict[str, tuple[str, str]]) -> None:
    """Assert every (label -> thunk) in *cases* is rejected with exactly the (code, message) in
    *expected[label]*."""
    actual = {label: _error_stable(thunk) for label, thunk in cases.items()}
    wrong = {k: v for k, v in actual.items() if v != expected[k]}
    assert not wrong, f"expected {expected} for every op, got mismatches: {wrong}"

def _error_stable(fn, attempts: int = 6):
    """Like ``_error`` but retries through throttling so the assertion observes
    the operation's real rejection code rather than a rate-limit artefact."""
    code, message = _error(fn)
    for attempt in range(attempts - 1):
        if code not in THROTTLE_CODES:
            break
        time.sleep(5 * (attempt + 1))
        code, message = _error(fn)
    return code, message

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Get/Put/RemoveManagedScalingPolicy reject an unknown cluster with ValidationException and each
    operation's exact message, including a Put whose limits are inverted."""
    emr = ctx.client("emr")
    j = UNKNOWN_CLUSTER_ID
    job_flow_invalid = "Specified job flow ID not valid."
    _assert_rejections(
        {
            "GetManagedScalingPolicy": lambda: emr.get_managed_scaling_policy(ClusterId=j),
            "PutManagedScalingPolicy": lambda: emr.put_managed_scaling_policy(
                ClusterId=j,
                ManagedScalingPolicy={
                    "ComputeLimits": {
                        "UnitType": "Instances",
                        "MinimumCapacityUnits": 1,
                        "MaximumCapacityUnits": 4,
                    }
                },
            ),
            "PutManagedScalingPolicyInverted": lambda: emr.put_managed_scaling_policy(
                ClusterId=j,
                ManagedScalingPolicy={
                    "ComputeLimits": {
                        "UnitType": "Instances",
                        "MinimumCapacityUnits": 8,
                        "MaximumCapacityUnits": 2,
                    }
                },
            ),
            "RemoveManagedScalingPolicy": lambda: emr.remove_managed_scaling_policy(
                ClusterId=j
            ),
        },
        {
            "GetManagedScalingPolicy": ("ValidationException", f"Cluster id '{j}' is not valid."),
            "PutManagedScalingPolicy": ("ValidationException", job_flow_invalid),
            "PutManagedScalingPolicyInverted": ("ValidationException", job_flow_invalid),
            "RemoveManagedScalingPolicy": ("ValidationException", job_flow_invalid),
        },
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
