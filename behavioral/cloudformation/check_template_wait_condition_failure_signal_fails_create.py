"""template-wait-condition-failure-signal-fails-create."""
from __future__ import annotations

import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-wait-condition-failure-signal-fails-create"
GROUP = "wait-conditions"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0
_REASON = "disk full on worker two"

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        "Wait": {
            "Type": "AWS::CloudFormation::WaitCondition",
            "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "600", "Count": 2},
        },
    },
})


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _signal(ctx, url: str, status: str, unique_id: str, reason: str) -> int:
    """PUT one wait-condition signal to the presigned handle URL; returns the HTTP status."""
    body = json.dumps({"Status": status, "Reason": reason, "UniqueId": unique_id, "Data": reason}).encode()
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(target, data=body, method="PUT", headers={"Content-Type": "", **route})
    with urllib.request.urlopen(req, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
        return resp.status


def _settle(cf, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {_DEADLINE_S}s")
        time.sleep(3.0)


def _delete_stack(cf, stack_id: str) -> None:
    """DeleteStack, then poll by StackId to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    # The first read after DeleteStack may still show the prior status, so only the two terminal
    # delete states end the poll.
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
            )
        time.sleep(3.0)


def _handle_url(cf, stack_id: str) -> str:
    """The handle's presigned URL, its PhysicalResourceId once the handle is created."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        try:
            detail = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Handle")["StackResourceDetail"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationError":
                raise
            detail = {}
        if detail.get("ResourceStatus") == "CREATE_COMPLETE":
            return detail["PhysicalResourceId"]
        if time.monotonic() > deadline:
            raise AssertionError(f"the handle of {stack_id} was not created within {_DEADLINE_S}s: {detail!r}")
        time.sleep(2.0)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Count 2 wait condition given one SUCCESS and one FAILURE signal fails with the exact
    "WaitCondition received failed message" reason naming the failing UniqueId, then rolls back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-waitcondition.html
    """
    cf = ctx.client("cloudformation")
    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-wcfail-"), TemplateBody=_TEMPLATE,
                               Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    url = _handle_url(cf, stack_id)
    assert not (p := ctx.published_url_mismatch(url)), p

    ok_id, bad_id = ctx.unique_name("ok-"), ctx.unique_name("bad-")
    assert _signal(ctx, url, "SUCCESS", ok_id, "worker one ready") == 200, "the SUCCESS signal PUT was refused"
    assert _signal(ctx, url, "FAILURE", bad_id, _REASON) == 200, "the FAILURE signal PUT was refused"

    final = _settle(cf, stack_id)
    assert final["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a FAILURE signal must fail the create; got {final['StackStatus']!r}: {final.get('StackStatusReason')!r}"
    )
    events = [e for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
              for e in page["StackEvents"]]
    reasons = [
        e.get("ResourceStatusReason") for e in events
        if e["LogicalResourceId"] == "Wait" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert reasons == [f"WaitCondition received failed message: '{_REASON}' for uniqueId: {bad_id}"], (
        f"the wait condition's failure reason differs: {reasons!r}"
    )
    stack_reasons = [
        e.get("ResourceStatusReason") for e in events
        if e["LogicalResourceId"] == final["StackName"] and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"
    ]
    assert stack_reasons == ["The following resource(s) failed to create: [Wait]. Rollback requested by user."], (
        f"the stack's rollback reason differs: {stack_reasons!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
