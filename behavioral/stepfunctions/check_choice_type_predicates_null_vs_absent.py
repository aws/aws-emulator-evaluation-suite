"""choice-type-predicates-null-vs-absent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-type-predicates-null-vs-absent"
GROUP = 'choice_state'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps(
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


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_sfn_role(ctx):
    """Create an execution role for this check's state machine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    return arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    # A fresh role takes a few seconds before Step Functions may assume it.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Choice Is* predicates route six inputs exactly: a JSON null is present and IsNull, an absent
    key is neither, and an RFC3339 string matches IsTimestamp (ordered before IsString).
    """
    definition = {
        "StartAt": "Classify",
        "States": {
            "Classify": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.v", "IsPresent": False, "Next": "Absent"},
                    {"Variable": "$.v", "IsNull": True, "Next": "Null"},
                    {"Variable": "$.v", "IsNumeric": True, "Next": "Numeric"},
                    {"Variable": "$.v", "IsBoolean": True, "Next": "Boolean"},
                    {"Variable": "$.v", "IsTimestamp": True, "Next": "Timestamp"},
                    {"Variable": "$.v", "IsString": True, "Next": "Str"},
                ],
                "Default": "Unclassified",
            },
            "Absent": {"Type": "Pass", "Result": "absent", "End": True},
            "Null": {"Type": "Pass", "Result": "null", "End": True},
            "Numeric": {"Type": "Pass", "Result": "numeric", "End": True},
            "Boolean": {"Type": "Pass", "Result": "boolean", "End": True},
            "Timestamp": {"Type": "Pass", "Result": "timestamp", "End": True},
            "Str": {"Type": "Pass", "Result": "string", "End": True},
            "Unclassified": {"Type": "Pass", "Result": "unclassified", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition)

    cases = [
        ({"other": 1}, "absent", "a missing $.v must satisfy IsPresent:false"),
        ({"v": None}, "null", "an explicit JSON null is PRESENT and IsNull:true, not absent"),
        ({"v": 7}, "numeric", "an integer must satisfy IsNumeric"),
        ({"v": 1.5}, "numeric", "a float must satisfy IsNumeric"),
        ({"v": True}, "boolean", "a JSON boolean is IsBoolean, never IsNumeric"),
        (
            {"v": "2024-01-01T00:00:00Z"},
            "timestamp",
            "an RFC3339 string must satisfy IsTimestamp, and IsTimestamp is listed before IsString "
            "so it must win",
        ),
        ({"v": "hello"}, "string", "a non-RFC3339 string is IsString but NOT IsTimestamp"),
        ({"v": {"nested": 1}}, "unclassified", "an object matches none of the six predicates"),
        ({"v": [1, 2]}, "unclassified", "an array matches none of the six predicates"),
    ]

    for input_data, expected, why in cases:
        desc = _wait_execution_complete(
            ctx, _start_execution(ctx, sm_arn, input_data=input_data), timeout_s=60
        )
        assert desc["status"] == "SUCCEEDED", (
            f"input {input_data!r} did not reach SUCCEEDED: {desc.get('status')} "
            f"error={desc.get('error')} cause={desc.get('cause')}"
        )
        got = _get_output(desc)
        assert got == expected, (
            f"input {input_data!r} routed to {got!r}, expected {expected!r} -- {why}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
