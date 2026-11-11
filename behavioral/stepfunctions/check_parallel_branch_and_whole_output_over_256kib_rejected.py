"""parallel-branch-and-whole-output-over-256kib-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parallel-branch-and-whole-output-over-256kib-rejected"
GROUP = 'quota'
SERVICES = ['stepfunctions']

_LIMIT = 256 * 1024
_OBJ_OVERHEAD = len(json.dumps({"blob": ""}, separators=(",", ":")).encode())
# "[" + first object + "," + second object + "]"
_ARRAY_OVERHEAD = len(json.dumps([{"a": 1}, {"a": 1}], separators=(",", ":")).encode()) - 2 * len(
    json.dumps({"a": 1}, separators=(",", ":")).encode()
)


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A Parallel branch whose own output exceeds the 256 KiB state payload limit fails the
    execution naming that branch; branches individually under the limit whose combined array
    output exceeds it fail naming the Parallel state itself, and output under the limit succeeds.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    # Scenario 1: branch B's own literal output alone exceeds the per-state limit; C stays tiny.
    # Literal Result blocks (not passed through from the execution input) so the input itself
    # -- which has its own, separate 256 KiB StartSyncExecution limit -- stays trivial.
    b_over = _blob(_LIMIT + 2048)
    sm_branch_over = _create_state_machine(ctx, _parallel_def(b_over, _blob(16)), role_arn)
    result = _start_sync(ctx, sm_branch_over, {})
    assert result["status"] == "FAILED", (
        f"a {_LIMIT + 2048}-byte branch output ended {result['status']!r}, expected FAILED: "
        f"{result.get('output')!r}"
    )
    assert result.get("error") == "States.DataLimitExceeded", (
        f"expected States.DataLimitExceeded, got {result.get('error')!r} / {result.get('cause')!r}"
    )
    expected_cause_branch = (
        "The state/task 'B' returned a result with a size exceeding the maximum number of "
        "bytes service limit."
    )
    assert result.get("cause") == expected_cause_branch, (
        f"expected cause {expected_cause_branch!r} naming branch state 'B', got {result.get('cause')!r}"
    )

    # Scenario 2: B and C are each individually well under the per-state limit, but the
    # Parallel's own output -- the array of both -- exceeds it.
    each_output = 150_000
    assert each_output < _LIMIT, "branch halves must individually stay under the limit"
    combined_over = 2 * each_output + _ARRAY_OVERHEAD
    assert combined_over > _LIMIT, f"combined size {combined_over!r} must exceed the limit {_LIMIT!r}"
    half_under = each_output - _OBJ_OVERHEAD
    b_half, c_half = _blob(half_under), _blob(half_under)
    sm_whole_over = _create_state_machine(ctx, _parallel_def(b_half, c_half), role_arn)
    result = _start_sync(ctx, sm_whole_over, {})
    assert result["status"] == "FAILED", (
        f"a {combined_over}-byte combined Parallel output ended {result['status']!r}, "
        f"expected FAILED: {result.get('output')!r}"
    )
    assert result.get("error") == "States.DataLimitExceeded", (
        f"expected States.DataLimitExceeded, got {result.get('error')!r} / {result.get('cause')!r}"
    )
    expected_cause_whole = (
        "The state/task 'A' returned a result with a size exceeding the maximum number of "
        "bytes service limit."
    )
    assert result.get("cause") == expected_cause_whole, (
        f"expected cause {expected_cause_whole!r} naming the Parallel state 'A', got {result.get('cause')!r}"
    )

    # Scenario 3: combined output comfortably under the limit succeeds with the array intact.
    each_output_under = 120_000
    assert 2 * each_output_under + _ARRAY_OVERHEAD < _LIMIT, "combined output must stay under the limit"
    under_each = each_output_under - _OBJ_OVERHEAD
    b_under, c_under = _blob(under_each), _blob(under_each)
    sm_under = _create_state_machine(ctx, _parallel_def(b_under, c_under), role_arn)
    result = _start_sync(ctx, sm_under, {})
    assert result["status"] == "SUCCEEDED", (
        f"a combined output under the limit ended {result['status']!r}: "
        f"{result.get('error')!r} {result.get('cause')!r}"
    )
    output = json.loads(result["output"])
    assert output == [{"blob": b_under}, {"blob": c_under}], (
        "the succeeding execution's output did not carry both branch blobs intact"
    )


def _parallel_def(b_blob: str, c_blob: str) -> dict:
    """A Parallel state 'A' with two Pass branches 'B' and 'C' returning the given literal blobs."""
    return {
        "Comment": "two Pass branches, each returning a fixed-size literal blob",
        "StartAt": "A",
        "States": {
            "A": {
                "Type": "Parallel",
                "Branches": [
                    {"StartAt": "B", "States": {
                        "B": {"Type": "Pass", "Result": {"blob": b_blob}, "End": True},
                    }},
                    {"StartAt": "C", "States": {
                        "C": {"Type": "Pass", "Result": {"blob": c_blob}, "End": True},
                    }},
                ],
                "End": True,
            }
        },
    }


def _blob(n: int) -> str:
    """An ``n``-character ASCII string."""
    assert n > 0, f"blob length must be positive, got {n!r}"
    return "x" * n


def _start_sync(ctx, sm_arn, payload):
    sfn = ctx.client("stepfunctions")
    return sfn.start_sync_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload),
    )


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    # IAM propagation exposes no condition to poll; the bounded AccessDeniedException retry in
    # _create_state_machine covers it.
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="EXPRESS",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(
                lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"
            ))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
