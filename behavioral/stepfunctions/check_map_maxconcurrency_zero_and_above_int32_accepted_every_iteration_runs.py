"""map-maxconcurrency-zero-and-above-int32-accepted-every-iteration-runs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-maxconcurrency-zero-and-above-int32-accepted-every-iteration-runs"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_ITEMS = [10, 20, 30, 40, 50]
_ABOVE_INT32 = 2147483648


def _trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _definition(max_concurrency: int) -> str:
    return json.dumps(
        {
            "Comment": "an inline Map whose MaxConcurrency is an edge value",
            "StartAt": "MapState",
            "States": {
                "MapState": {
                    "Type": "Map",
                    "ItemsPath": "$.items",
                    "MaxConcurrency": max_concurrency,
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "INLINE"},
                        "StartAt": "Double",
                        "States": {
                            "Double": {
                                "Type": "Pass",
                                "Parameters": {"doubled.$": "States.MathAdd($.n, $.n)"},
                                "End": True,
                            }
                        },
                    },
                    "End": True,
                }
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmapmcc-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy(),
        Path="/sim2real/",
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str, max_concurrency: int) -> str:
    """A STANDARD state machine whose Map carries ``max_concurrency``, retrying only the
    AccessDeniedException raised while the freshly created role's assume-role grant
    propagates, polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnmapmcc-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_definition(max_concurrency),
                roleArn=role_arn,
                type="STANDARD",
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        f"CreateStateMachine still AccessDenied 120s after the role was created. "
        f"Last error: {last}"
    )


def _start_execution(ctx, sm_arn: str, input_data: dict) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(input_data))[
        "executionArn"
    ]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_terminal(ctx, exec_arn: str, *, deadline_s: float = 90.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {deadline_s}s: {last!r}")


def _run_one(ctx, role_arn: str, max_concurrency: int) -> list:
    sm_arn = _create_state_machine(ctx, role_arn, max_concurrency)
    exec_arn = _start_execution(ctx, sm_arn, {"items": [{"n": n} for n in _ITEMS]})
    result = _wait_terminal(ctx, exec_arn)
    assert result["status"] == "SUCCEEDED", (
        f"a Map with MaxConcurrency={max_concurrency} over {len(_ITEMS)} items must "
        f"SUCCEED; got status={result['status']!r} error={result.get('error')!r} "
        f"cause={result.get('cause')!r}"
    )
    return [o["doubled"] for o in json.loads(result["output"])]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Map's MaxConcurrency of 0 (explicit, not omitted) and of a value one above the
    signed-32-bit integer maximum are both accepted and every iteration still runs."""
    role_arn = _create_sfn_role(ctx)
    expected = [n + n for n in _ITEMS]

    zero_output = _run_one(ctx, role_arn, 0)
    assert zero_output == expected, (
        f"MaxConcurrency=0 must run every one of the {len(_ITEMS)} iterations and return "
        f"their results in item order; expected {expected!r}, got {zero_output!r}"
    )

    overflow_output = _run_one(ctx, role_arn, _ABOVE_INT32)
    assert overflow_output == expected, (
        f"MaxConcurrency={_ABOVE_INT32} (one above the signed-32-bit integer maximum) "
        f"must still run every one of the {len(_ITEMS)} iterations and return their "
        f"results in item order; expected {expected!r}, got {overflow_output!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
