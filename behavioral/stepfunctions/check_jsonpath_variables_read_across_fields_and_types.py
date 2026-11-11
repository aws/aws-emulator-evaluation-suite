"""jsonpath-variables-read-across-fields-and-types."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonpath-variables-read-across-fields-and-types"
GROUP = 'variables'
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
    """An execution role granting only GetCallerIdentity, for the in-check Task probe."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="get-caller-identity",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:GetCallerIdentity",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="get-caller-identity"))
    )
    return arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
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


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s=60, max_attempts=6):
    """Start an execution and poll it to terminal; restart only on the IAM-propagation race."""
    desc = None
    for attempt in range(max_attempts):
        desc = _wait_execution_complete(
            ctx, _start_execution(ctx, sm_arn, input_data=input_data), timeout_s=timeout_s
        )
        cause = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in cause for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5 + attempt * 3)
    return desc


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """In JSONPath mode, `$var`/`$var.path` assigned with `Assign`'s `"x.$"` form, for every JSON
    value type, is readable from InputPath, OutputPath, Parameters, ResultSelector, ItemsPath,
    ItemSelector and an intrinsic argument, and a Parallel branch sees its outer scope's variables.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/workflow-variables.html
    """
    role_arn = _create_sfn_role(ctx)
    definition = {
        "StartAt": "Seed",
        "States": {
            "Seed": {
                "Type": "Pass",
                "Assign": {
                    "sVar.$": "$.str",
                    "nVar.$": "$.num",
                    "bVar.$": "$.flag",
                    "zVar.$": "$.nil",
                    "aVar.$": "$.arr",
                    "oVar.$": "$.obj",
                    "wVar.$": "$.waitSecs",
                },
                "Next": "Fanout",
            },
            "Fanout": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "NullProbe",
                        "States": {
                            # Pass reading a null-typed variable via OutputPath.
                            "NullProbe": {"Type": "Pass", "OutputPath": "$zVar", "End": True},
                        },
                    },
                    {
                        "StartAt": "SucceedProbe",
                        "States": {
                            # Succeed rebasing on an object-typed variable via InputPath, then
                            # a plain path on the rebased document via OutputPath.
                            "SucceedProbe": {
                                "Type": "Succeed",
                                "InputPath": "$oVar",
                                "OutputPath": "$.inner",
                            },
                        },
                    },
                    {
                        "StartAt": "WaitProbe",
                        "States": {
                            # Wait reading its own SecondsPath from a variable, and OutputPath
                            # selecting a boolean-typed variable whole.
                            "WaitProbe": {
                                "Type": "Wait",
                                "SecondsPath": "$wVar",
                                "OutputPath": "$bVar",
                                "End": True,
                            },
                        },
                    },
                    {
                        "StartAt": "ChoiceProbe",
                        "States": {
                            # Choice's InputPath rebased on an object-typed variable.
                            "ChoiceProbe": {
                                "Type": "Choice",
                                "InputPath": "$oVar",
                                "Choices": [
                                    {"Variable": "$.count", "NumericGreaterThan": 5, "Next": "Big"}
                                ],
                                "Default": "Small",
                            },
                            "Big": {"Type": "Pass", "Result": "big", "End": True},
                            "Small": {"Type": "Pass", "Result": "small", "End": True},
                        },
                    },
                    {
                        "StartAt": "TaskProbe",
                        "States": {
                            # Task ResultSelector reading variables: an intrinsic over a string
                            # variable, an indexed read on an array variable, and a nested read on
                            # an object variable -- independent of the task's own result.
                            "TaskProbe": {
                                "Type": "Task",
                                "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
                                "Parameters": {},
                                "ResultSelector": {
                                    "echoed.$": "States.Format('v={}', $sVar)",
                                    "fromArr.$": "$aVar[1]",
                                    "fromObj.$": "$oVar.inner",
                                },
                                "End": True,
                            },
                        },
                    },
                    {
                        "StartAt": "MapProbe",
                        "States": {
                            # Map's ItemsPath sourced from an array variable, and ItemSelector
                            # reading an OUTER-scope object variable's nested field alongside the
                            # per-item context value.
                            "MapProbe": {
                                "Type": "Map",
                                "ItemsPath": "$aVar",
                                "ItemSelector": {
                                    "val.$": "$$.Map.Item.Value",
                                    "fromOuterVar.$": "$oVar.count",
                                },
                                "ItemProcessor": {
                                    "ProcessorConfig": {"Mode": "INLINE"},
                                    "StartAt": "Mult",
                                    "States": {
                                        "Mult": {
                                            "Type": "Pass",
                                            "Parameters": {
                                                "product.$": "States.MathAdd($.val, $.fromOuterVar)"
                                            },
                                            "End": True,
                                        },
                                    },
                                },
                                "End": True,
                            },
                        },
                    },
                ],
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    input_data = {
        "str": "hello",
        "num": 42,
        "flag": True,
        "nil": None,
        "arr": [10, 20, 30],
        "obj": {"inner": "deep", "count": 7},
        "waitSecs": 1,
    }
    desc = _run_to_terminal(ctx, sm_arn, input_data)
    assert desc["status"] == "SUCCEEDED", (
        f"execution did not succeed: status={desc.get('status')} error={desc.get('error')!r} "
        f"cause={desc.get('cause')!r}"
    )
    output = _get_output(desc)
    expected = [
        None,
        "deep",
        True,
        "big",
        {"echoed": "v=hello", "fromArr": 20, "fromObj": "deep"},
        [{"product": 17}, {"product": 27}, {"product": 37}],
    ]
    assert output == expected, (
        f"Parallel branch outputs were {output!r}, expected {expected!r} -- each branch exercises "
        f"one state type's variable-reading field(s); a mismatch names which branch/field is wrong"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
