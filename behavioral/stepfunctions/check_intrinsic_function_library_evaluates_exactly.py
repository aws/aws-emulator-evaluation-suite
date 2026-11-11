"""intrinsic-function-library-evaluates-exactly."""
from __future__ import annotations

import hashlib
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "intrinsic-function-library-evaluates-exactly"
GROUP = 'intrinsic_functions'
SERVICES = ['stepfunctions']


# ===== helpers =====
_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_execution_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
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
# ===== end helpers =====

_UUID_V4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The ASL intrinsic function library, including a nested Base64Decode(Base64Encode(...)) call,
    evaluates to exact values in one Pass state; States.UUID is pinned to its v4 shape.
    """
    definition = {
        "StartAt": "Evaluate",
        "States": {
            "Evaluate": {
                "Type": "Pass",
                "Parameters": {
                    "partitioned.$": "States.ArrayPartition($.nums, 3)",
                    "contains.$": "States.ArrayContains($.nums, 5)",
                    "missing.$": "States.ArrayContains($.nums, 99)",
                    "range.$": "States.ArrayRange(1, 9, 2)",
                    "item.$": "States.ArrayGetItem($.nums, 2)",
                    "length.$": "States.ArrayLength($.nums)",
                    "unique.$": "States.ArrayUnique($.dupes)",
                    "formatted.$": "States.Format('{}/{} at {}', $.a, $.b, $.n)",
                    "split.$": "States.StringSplit($.csv, ',')",
                    "encoded.$": "States.Base64Encode($.a)",
                    "roundtrip.$": "States.Base64Decode(States.Base64Encode($.a))",
                    "hashed.$": "States.Hash($.a, 'SHA-256')",
                    "sum.$": "States.MathAdd($.n, -3)",
                    "merged.$": "States.JsonMerge($.o1, $.o2, false)",
                    "uuid.$": "States.UUID()",
                },
                "End": True,
            }
        },
    }
    input_data = {
        "nums": [1, 2, 3, 4, 5, 6, 7],
        "dupes": [1, 2, 3, 3, 3, 4, 4],
        "a": "hello",
        "b": "world",
        "n": 10,
        "csv": "a,b,c",
        "o1": {"x": 1, "y": 1},
        "o2": {"y": 2, "z": 3},
    }
    desc = _wait_execution_complete(
        ctx,
        _start_execution(ctx, _create_state_machine(ctx, definition), input_data=input_data),
        timeout_s=60,
    )
    assert desc["status"] == "SUCCEEDED", (
        f"intrinsic evaluation must succeed, got {desc.get('status')} "
        f"error={desc.get('error')} cause={desc.get('cause')}"
    )
    out = _get_output(desc)

    expected = {
        "partitioned": [[1, 2, 3], [4, 5, 6], [7]],
        "contains": True,
        "missing": False,
        "range": [1, 3, 5, 7, 9],
        "item": 3,
        "length": 7,
        "unique": [1, 2, 3, 4],
        "formatted": "hello/world at 10",
        "split": ["a", "b", "c"],
        "encoded": "aGVsbG8=",
        "roundtrip": "hello",
        "hashed": hashlib.sha256(b"hello").hexdigest(),
        "sum": 7,
        "merged": {"x": 1, "y": 2, "z": 3},
    }
    for key, want in expected.items():
        assert key in out, f"intrinsic result {key!r} missing from output {out!r}"
        assert out[key] == want, f"States intrinsic for {key!r}: expected {want!r}, got {out[key]!r}"
    # States.MathAdd with a negative addend must subtract, and the result must stay an integer.
    assert isinstance(out["sum"], int), (
        f"States.MathAdd(10, -3) must yield the integer 7, got {out['sum']!r}"
    )
    # ArrayContains(false) must be a real JSON false, not an omitted/None key.
    assert out["missing"] is False, (
        f"States.ArrayContains for an absent value must be JSON false, got {out['missing']!r}"
    )
    assert isinstance(out.get("uuid"), str) and _UUID_V4.match(out["uuid"]), (
        f"States.UUID() must return an RFC 4122 v4 UUID, got {out.get('uuid')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
