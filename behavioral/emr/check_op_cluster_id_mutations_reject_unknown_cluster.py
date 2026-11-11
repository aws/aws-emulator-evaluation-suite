"""op-cluster-id-mutations-reject-unknown-cluster."""
from __future__ import annotations

import time

from behavioral_harness import tags

INSTANCE_TYPE = "m5.xlarge"

def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _default_role_arn(ctx, role_name="EMR_DefaultRole"):
    return f"arn:aws:iam::{_account_id(ctx)}:role/{role_name}"

CHECK = "op-cluster-id-mutations-reject-unknown-cluster"
GROUP = 'overly-permissive'
SERVICES = ['emr']

THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")

UNKNOWN_CLUSTER_ID = "j-" + "Z" * 13

UNKNOWN_STEP_ID = "s-" + "Z" * 13

def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")

def _assert_codes(cases: dict, expected: dict[str, tuple[str, str]]) -> None:
    """Assert every (label -> thunk) in *cases* is rejected with exactly the (code, message) in
    *expected*; real EMR words this per op, some echoing the cluster id and others not.
    """
    results = {label: _error_stable(thunk) for label, thunk in cases.items()}
    assert results == expected, f"expected rejections {expected}, got {results}"

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
    """ModifyCluster, CancelSteps, AddInstanceFleet and GetClusterSessionCredentials reject an unknown
    cluster with InvalidRequestException and each operation's exact message."""
    emr = ctx.client("emr")
    j = UNKNOWN_CLUSTER_ID
    _assert_codes(
        {
            "ModifyCluster": lambda: emr.modify_cluster(ClusterId=j, StepConcurrencyLevel=2),
            "CancelSteps": lambda: emr.cancel_steps(ClusterId=j, StepIds=[UNKNOWN_STEP_ID]),
            "AddInstanceFleet": lambda: emr.add_instance_fleet(
                ClusterId=j,
                InstanceFleet={
                    "Name": "Task",
                    "InstanceFleetType": "TASK",
                    "TargetOnDemandCapacity": 1,
                    "InstanceTypeConfigs": [{"InstanceType": INSTANCE_TYPE}],
                },
            ),
            "GetClusterSessionCredentials": lambda: emr.get_cluster_session_credentials(
                ClusterId=j, ExecutionRoleArn=_default_role_arn(ctx, "EMR_DefaultRole")
            ),
        },
        {
            "ModifyCluster": ("InvalidRequestException", f"Cluster id '{j}' is not valid."),
            "CancelSteps": ("InvalidRequestException", f"Cluster id '{j}' is not valid."),
            "AddInstanceFleet": ("InvalidRequestException", "Specified job flow ID not valid."),
            "GetClusterSessionCredentials": ("InvalidRequestException", "Cluster id is not valid."),
        },
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
