"""cfn-events-api-destination-update-nonexistent-connection-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-events-api-destination-update-nonexistent-connection-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "events"]

_STACK_CAP_S = 600.0
_ENDPOINT = "https://example.com/sim2real-endpoint"
_HANDLER_LINE = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _connection(name: str, secret_ref: str) -> dict:
    return {
        "Type": "AWS::Events::Connection",
        "Properties": {
            "Name": name,
            "AuthorizationType": "API_KEY",
            "AuthParameters": {
                "ApiKeyAuthParameters": {
                    "ApiKeyName": "sim2real-auth-header", "ApiKeyValue": {"Ref": secret_ref},
                }
            },
        },
    }


def _destination(name: str, connection_arn) -> dict:
    return {
        "Type": "AWS::Events::ApiDestination",
        "Properties": {
            "Name": name, "ConnectionArn": connection_arn, "InvocationEndpoint": _ENDPOINT,
            "HttpMethod": "POST",
        },
    }


def _template(resources: dict, outputs: dict) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Secret": {"Type": "String", "NoEcho": True}},
        "Resources": resources,
        "Outputs": outputs,
    })


@tags(
    "axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control",
)
def run(ctx) -> None:
    """A stack update pointing an AWS::Events::ApiDestination's ConnectionArn at a connection
    that does not exist is refused and rolled back to the destination's prior ConnectionArn;
    the same stack then updates the destination to a second, real connection successfully.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-apidestination.html
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")

    conn_a = ctx.unique_name("sim2real-behav-evconn-a-")
    conn_b = ctx.unique_name("sim2real-behav-evconn-b-")
    dest_name = ctx.unique_name("sim2real-behav-evdest-")
    stack_name = ctx.unique_name("sim2real-behav-evdestupd-stack-")
    secret = ctx.unique_name("sim2real-api-key-")

    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: Destination points at Connection A -------------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(
            {
                "ConnA": _connection(conn_a, "Secret"),
                "Destination": _destination(dest_name, {"Fn::GetAtt": ["ConnA", "Arn"]}),
            },
            {"ConnAArn": {"Value": {"Fn::GetAtt": ["ConnA", "Arn"]}}},
        ),
        Parameters=[{"ParameterKey": "Secret", "ParameterValue": secret}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    stack = _settle(ctx, cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    conn_a_arn = _outputs(stack)["ConnAArn"]
    dest = events.describe_api_destination(Name=dest_name)
    assert dest["ConnectionArn"] == conn_a_arn, f"initial ConnectionArn {dest['ConnectionArn']!r}"

    # ---- 2. the negative: update ConnectionArn to a connection that was never created ------
    missing_name = ctx.unique_name("sim2real-behav-evconn-missing-")
    missing_uuid = str(uuid.uuid4())
    missing_arn = {
        "Fn::Sub": "arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}"
                   f":connection/{missing_name}/{missing_uuid}"
    }
    before = len(_events(cfn, stack_id))
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(
            {
                "ConnA": _connection(conn_a, "Secret"),
                "Destination": _destination(dest_name, missing_arn),
            },
            {"ConnAArn": {"Value": {"Fn::GetAtt": ["ConnA", "Arn"]}}},
        ),
        Parameters=[{"ParameterKey": "Secret", "ParameterValue": secret}],
    )
    stack = _settle(ctx, cfn, stack_id)
    assert stack["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"the bad update ended {stack['StackStatus']!r}, not UPDATE_ROLLBACK_COMPLETE"
    )
    rows = _events(cfn, stack_id)[before:]
    failed = [e.get("ResourceStatusReason") for e in rows
              if e["LogicalResourceId"] == "Destination" and e["ResourceStatus"] == "UPDATE_FAILED"]
    assert len(failed) == 1, f"expected one Destination UPDATE_FAILED row, got {failed!r}"
    partition = stack_id.split(":")[1]
    message, code = _handler_reason(failed[0], ctx.account)
    want_message = (
        "Failed to update the api-destination(s). Connection "
        f"'arn:{partition}:events:{ctx.region}:<account>:connection/{missing_name}/{missing_uuid}' "
        "does not exist. (Service: EventBridge, Status Code: 400, Request ID: <id>) "
        "(SDK Attempt Count: <n>)"
    )
    assert (message, code) == (want_message, "NotFound"), (
        f"handler reason ({message!r}, {code!r}), expected ({want_message!r}, 'NotFound')"
    )
    # the rollback must leave the destination exactly as it was before the rejected update
    dest = events.describe_api_destination(Name=dest_name)
    assert dest["ConnectionArn"] == conn_a_arn, (
        f"a rolled-back update must restore ConnectionArn {conn_a_arn!r}, got {dest['ConnectionArn']!r}"
    )

    # ---- 3. positive control: the same stack updates to a second, real connection ---------
    before = len(_events(cfn, stack_id))
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(
            {
                "ConnA": _connection(conn_a, "Secret"),
                "ConnB": _connection(conn_b, "Secret"),
                "Destination": _destination(dest_name, {"Fn::GetAtt": ["ConnB", "Arn"]}),
            },
            {
                "ConnAArn": {"Value": {"Fn::GetAtt": ["ConnA", "Arn"]}},
                "ConnBArn": {"Value": {"Fn::GetAtt": ["ConnB", "Arn"]}},
            },
        ),
        Parameters=[{"ParameterKey": "Secret", "ParameterValue": secret}],
    )
    stack = _settle(ctx, cfn, stack_id)
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"the control update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    rows = _events(cfn, stack_id)[before:]
    failed = [r for r in rows if r["ResourceStatus"].endswith("_FAILED")]
    assert failed == [], f"the control update must not fail any resource: {failed!r}"
    conn_b_arn = _outputs(stack)["ConnBArn"]
    dest = events.describe_api_destination(Name=dest_name)
    assert dest["ConnectionArn"] == conn_b_arn, (
        f"the control update must move ConnectionArn to {conn_b_arn!r}, got {dest['ConnectionArn']!r}"
    )


def _handler_reason(reason: str, account: str) -> tuple[str, str]:
    """``(message, HandlerErrorCode)`` of a registry-handler failure reason, request id masked."""
    m = _HANDLER_LINE.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    message = m["message"].replace(account, "<account>")
    message = re.sub(r"(?:Extended )?Request ID: [^,;)]+", "Request ID: <id>", message)
    message = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", message)
    return message, m["code"]


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 3.0):
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    return _poll(
        ctx, lambda: _stack(cfn, stack_id), lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_CAP_S, what=f"stack {stack_id} settled",
    )


def _outputs(stack: dict) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _events(cfn, stack_id: str) -> list[dict]:
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by name and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None, lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_CAP_S, what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None, lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), cap_s=_STACK_CAP_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} teardown ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
