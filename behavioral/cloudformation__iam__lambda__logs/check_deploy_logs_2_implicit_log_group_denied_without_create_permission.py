"""deploy-logs-2-implicit-log-group-denied-without-create-permission."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-logs-2-implicit-log-group-denied-without-create-permission"

GROUP = "deploy-implicit-log-group"

SERVICES = ["cloudformation", "iam", "lambda", "logs"]

_ROLE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

_CODE = (
    "def handler(event, context):\n"
    "    print('SIM2REAL_MARKER ' + event['marker'])\n"
    "    return {'marker': event['marker'],\n"
    "            'log_group': context.log_group_name,\n"
    "            'log_stream': context.log_stream_name}\n"
)


def _function(name_param: str, role: str) -> dict:
    return {
        "Type": "AWS::Lambda::Function",
        "Properties": {
            "FunctionName": {"Ref": name_param},
            "Runtime": "python3.12",
            "Handler": "index.handler",
            "Role": {"Fn::GetAtt": [role, "Arn"]},
            "Timeout": 30,
            "Code": {"ZipFile": _CODE},
        },
    }


# One stack, two functions, no AWS::Logs resources at all. The control role carries the
# AWS-managed basic execution policy; the other role may write streams and events into its own
# implicit group's ARN but may NOT create the group.
_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "sim2real: implicit Lambda log groups with and without logs:CreateLogGroup.",
    "Parameters": {
        "ControlName": {"Type": "String"},
        "NoCreateName": {"Type": "String"},
    },
    "Resources": {
        "ControlRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": _ROLE_TRUST,
                "ManagedPolicyArns": [
                    {
                        "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/service-role/"
                        "AWSLambdaBasicExecutionRole"
                    }
                ],
            },
        },
        "NoCreateRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": _ROLE_TRUST,
                "Policies": [
                    {
                        "PolicyName": "write-but-not-create",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                                    "Resource": {
                                        "Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:"
                                        "${AWS::AccountId}:log-group:/aws/lambda/"
                                        "${NoCreateName}:*"
                                    },
                                }
                            ],
                        },
                    }
                ],
            },
        },
        "ControlFunction": _function("ControlName", "ControlRole"),
        "NoCreateFunction": _function("NoCreateName", "NoCreateRole"),
    },
}

_SUSTAIN_ROUNDS = 3


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda role without logs:CreateLogGroup leaves no implicit `/aws/lambda/<fn>` group while
    its invokes succeed and a control function keeps logging; once the group is created out of
    band, the same role's log lines land in it.
    """
    logs = ctx.client("logs")
    awslambda = ctx.client("lambda")
    cfn = ctx.client("cloudformation")

    control_fn = _xname(ctx, "ctlfn")
    control_group = f"/aws/lambda/{control_fn}"
    nocreate_fn = _xname(ctx, "nocfn")
    nocreate_group = f"/aws/lambda/{nocreate_fn}"
    # Registered before the functions exist, so LIFO runs them after the stack delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, control_group))
    ctx.on_cleanup(lambda: _reap_log_group(logs, nocreate_group))

    stack_name = _xname(ctx, "stk")
    _create_stack(
        ctx, stack_name, _TEMPLATE, {"ControlName": control_fn, "NoCreateName": nocreate_fn}
    )
    status = _wait_stack_terminal(cfn, stack_name, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended in {status!r}: {_failed_events(cfn, stack_name)!r}"
    )
    for fn in (control_fn, nocreate_fn):
        awslambda.get_waiter("function_active_v2").wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    # 1. Barrier: the first no-create invoke goes out, then the control side is driven until it
    #    lands (this also absorbs the control role's IAM propagation).
    denied_markers = [_invoke_ok(ctx, awslambda, nocreate_fn)["marker"]]
    _invoke_until_logged(ctx, awslambda, logs, control_fn, control_group)

    # 2. Sustained good side: each round invokes BOTH functions, and the control's line must land
    #    before the round counts. The no-create group must stay absent throughout.
    for _ in range(_SUSTAIN_ROUNDS):
        denied_markers.append(_invoke_ok(ctx, awslambda, nocreate_fn)["marker"])
        _invoke_until_logged(ctx, awslambda, logs, control_fn, control_group, attempts=1)
        present = _exact_group(logs, nocreate_group)
        assert present is None, (
            f"{nocreate_group} was created although its role lacks logs:CreateLogGroup: "
            f"{present!r}"
        )
    control = _exact_group(logs, control_group)
    assert control is not None, f"control group {control_group} absent after delivering lines"

    # 3. Repair exactly the one missing thing -- the group -- out of band, then the SAME role's
    #    writes land in it.
    logs.create_log_group(logGroupName=nocreate_group)
    ctx.on_cleanup(lambda: _reap_log_group(logs, nocreate_group))
    repaired = _exact_group(logs, nocreate_group)
    assert repaired is not None, f"create_log_group({nocreate_group!r}) is not visible"
    # Recycle the execution environments so the next invoke starts a fresh log pipeline; a warm
    # sandbox's agent state after the denied create is not something this check asserts on.
    awslambda.update_function_configuration(
        FunctionName=nocreate_fn, Environment={"Variables": {"SIM2REAL_REPAIRED": "1"}}
    )
    awslambda.get_waiter("function_updated_v2").wait(FunctionName=nocreate_fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    marker, payload, _rid, event = _invoke_until_logged(
        ctx, awslambda, logs, nocreate_fn, nocreate_group
    )
    assert event["logStreamName"] == payload["log_stream"], (event, payload)
    after = _exact_group(logs, nocreate_group)
    assert after is not None and after["creationTime"] == repaired["creationTime"], (
        f"the out-of-band group was replaced: {repaired!r} -> {after!r}"
    )
    assert "retentionInDays" not in after, after


_XSVC_PREFIX = "sim2real-xsvc-"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")},
    ]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _exact_group(logs, name: str) -> dict | None:
    """The one log group whose name is exactly `name` (prefix listing, paginated)."""
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page.get("logGroups", []):
            if g["logGroupName"] == name:
                return g
    return None


def _invoke_ok(ctx, awslambda, function_name: str) -> dict:
    """One synchronous invoke that must succeed; logging failures never fail an invoke."""
    marker = ctx.unique_name("m-")
    resp = awslambda.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps({"marker": marker}).encode(),
    )
    body = resp["Payload"].read().decode()
    assert not resp.get("FunctionError"), f"{function_name} raised: {body}"
    payload = json.loads(body)
    assert payload["marker"] == marker, payload
    return payload


def _invoke_until_logged(ctx, awslambda, logs, function_name, group, *, attempts=4, wait_s=60.0):
    """Invoke with a fresh marker until that marker is readable in `group`. Bounded: a missing
    line after every attempt is a FAIL naming the last state observed. Re-invoking is the bounded
    retry at first use of a freshly created role's permissions."""
    last = None
    for _ in range(attempts):
        marker = ctx.unique_name("m-")
        resp = awslambda.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps({"marker": marker}).encode(),
        )
        body = resp["Payload"].read().decode()
        assert not resp.get("FunctionError"), f"{function_name} raised: {body}"
        request_id = resp["ResponseMetadata"]["HTTPHeaders"]["x-amzn-requestid"]
        payload = json.loads(body)
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            try:
                events = logs.filter_log_events(
                    logGroupName=group, filterPattern=f'"{marker}"'
                ).get("events", [])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                events = []
            hit = [e for e in events if f"SIM2REAL_MARKER {marker}" in e["message"]]
            if hit:
                return marker, payload, request_id, hit[0]
            last = events
            time.sleep(5.0)
    raise AssertionError(
        f"no SIM2REAL_MARKER line reached {group} after {attempts} invokes; last {last!r}"
    )


def _create_stack(ctx, name: str, template: dict, parameters: dict) -> None:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=600.0))


def _wait_stack_terminal(cfn, name: str, *, timeout_s: float) -> str:
    terminal = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    return _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in terminal,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"stack {name} terminal",
    )


def _failed_events(cfn, name: str) -> list:
    out: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=name):
        out.extend(
            (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
            for e in page.get("StackEvents", [])
            if e["ResourceStatus"].endswith("FAILED")
        )
    return out


def _delete_stack_and_wait(ctx, name: str, *, timeout_s: float = 600.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    status = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {name}",
    )
    if status == "DELETE_FAILED":
        raise RuntimeError(f"stack {name} DELETE_FAILED: {_failed_events(cfn, name)!r}")


def _reap_log_group(logs, name: str, *, rounds: int = 4, settle_s: float = 15.0) -> None:
    """Delete `name`, then watch for a late flush recreating it; re-delete within a bound and
    raise rather than hang if it never converges."""
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise RuntimeError(f"delete_log_group {name}: {exc}") from exc
        time.sleep(settle_s)
        if _exact_group(logs, name) is None:
            return
    raise RuntimeError(f"log group {name} kept reappearing after {rounds} deletes")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
