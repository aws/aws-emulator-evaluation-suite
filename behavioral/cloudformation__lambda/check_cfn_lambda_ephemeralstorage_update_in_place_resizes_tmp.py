"""cfn-lambda-ephemeralstorage-update-in-place-resizes-tmp."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-ephemeralstorage-update-in-place-resizes-tmp"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "logs"]

_STACK_CAP_S = 300.0
_POLL_S = 2.0
_TARGET_MB = 620
_SMALL_SIZE_MB = 512
_LARGE_SIZE_MB = 2048

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

_HANDLER = (
    "import errno\n"
    "import os\n"
    "\n"
    "CHUNK = b'\\0' * (4 * 1024 * 1024)\n"
    "\n"
    "\n"
    "def handler(event, context):\n"
    "    path = '/tmp/sim2real-fill.bin'\n"
    "    target_mb = int(event['target_mb'])\n"
    "    written_mb = 0\n"
    "    err_errno = None\n"
    "    try:\n"
    "        with open(path, 'wb') as fh:\n"
    "            while written_mb < target_mb:\n"
    "                fh.write(CHUNK)\n"
    "                fh.flush()\n"
    "                written_mb += 4\n"
    "    except OSError as exc:\n"
    "        err_errno = exc.errno\n"
    "    finally:\n"
    "        if os.path.exists(path):\n"
    "            os.remove(path)\n"
    "    return {'written_mb': written_mb, 'errno': err_errno}\n"
)


def _template(function_name: str, size_mb: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                    "Code": {"ZipFile": _HANDLER},
                    "Timeout": 30,
                    "MemorySize": 256,
                    "EphemeralStorage": {"Size": size_mb},
                    "Tags": _TAGS,
                },
            },
        },
        "Outputs": {
            "FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}},
        },
    })


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation-deployed function's EphemeralStorage.Size reads back through Lambda,
    updates in place with no replacement, and the enforced /tmp limit tracks the new value:
    a write that overflows the small size succeeds once the stack raises it.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-ephemeralstorage.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-cfnes-fn-")
    stack_name = ctx.unique_name("sim2real-cfnes-stack-")
    ref = {"stack": stack_name}

    # Registered before the function exists so LIFO reaps its log group, which a buffered
    # invocation can recreate after the stack delete, only after that delete has happened.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: Size is the small end of the documented range
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(name, _SMALL_SIZE_MB),
        Capabilities=["CAPABILITY_IAM"], Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Fn"] == name, (
        f"the function's physical id must be its FunctionName {name!r}"
    )
    _assert_size(lam, name, _SMALL_SIZE_MB)

    small_result = _invoke(lam, name, _TARGET_MB)
    assert small_result["errno"] == 28, (
        f"writing {_TARGET_MB}MB into a {_SMALL_SIZE_MB}MB /tmp must hit ENOSPC, got {small_result!r}"
    )
    assert small_result["written_mb"] < _TARGET_MB, (
        f"a write that overflows {_SMALL_SIZE_MB}MB must not complete, got {small_result!r}"
    )

    # ---- 2. in-place update: EphemeralStorage.Size is not create-only
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(name, _LARGE_SIZE_MB),
        Capabilities=["CAPABILITY_IAM"], Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Fn"] == name, (
        "an EphemeralStorage.Size update must keep the same function, not replace it"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Fn"), name)
    _assert_size(lam, name, _LARGE_SIZE_MB)

    large_result = _invoke(lam, name, _TARGET_MB)
    assert large_result == {"written_mb": _TARGET_MB, "errno": None}, (
        f"the same write must complete once Size is raised to {_LARGE_SIZE_MB}MB, got {large_result!r}"
    )

    # ---- 3. delete: Lambda no longer knows the function
    _delete_stack(ctx, cfn, ref["stack"])
    fn_arn = _outputs(stack)["FnArn"]
    got = _wait_error(ctx, lambda: lam.get_function(FunctionName=name), "ResourceNotFoundException")
    want = ("ResourceNotFoundException", f"Function not found: {fn_arn}")
    assert got == want, f"GetFunction after the stack delete answered {got!r}, expected {want!r}"


def _assert_size(lam, name: str, size_mb: int) -> None:
    config = lam.get_function_configuration(FunctionName=name)
    got = config.get("EphemeralStorage", {}).get("Size")
    assert got == size_mb, f"GetFunctionConfiguration {name} EphemeralStorage.Size={got!r}, expected {size_mb}"


def _invoke(lam, name: str, target_mb: int) -> dict:
    resp = lam.invoke(FunctionName=name, Payload=json.dumps({"target_mb": target_mb}).encode())
    body = resp["Payload"].read().decode()
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"Invoke {name} answered {resp['StatusCode']} {resp.get('FunctionError')!r}: {body!r}"
    )
    return json.loads(body)


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group *name* until *reads* consecutive reads find it absent.

    A buffered log stream can recreate the group after the delete that was meant to remove it,
    so one delete is not a teardown; raises if it keeps coming back past its own budget.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        present = any(
            g["logGroupName"] == name
            for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        )
        if present:
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"{name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


# ===== CloudFormation polling and inspection helpers =====


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _settle(ctx, cfn, stack_id: str) -> dict:
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s")
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    return [
        (e["ResourceStatus"], e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str) -> None:
    statuses = [status for status, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"the function must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][1] == physical_id, (
        f"the update must complete on {physical_id!r}, its events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str):
    timeout = _budget_s(ctx, 120.0)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"still answering after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _stack_status_or_gone(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return "GONE"
        raise


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    status = _stack_status_or_gone(cfn, ref["stack"])
    if status == "GONE":
        return
    if status.endswith("_IN_PROGRESS"):
        _settle(ctx, cfn, ref["stack"])
    _delete_stack(ctx, cfn, ref["stack"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
