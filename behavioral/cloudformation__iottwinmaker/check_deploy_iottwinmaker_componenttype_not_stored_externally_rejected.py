"""deploy-iottwinmaker-componenttype-not-stored-externally-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iottwinmaker-componenttype-not-stored-externally-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "iottwinmaker"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "Time series property Temperature must be marked as isStoredExternally true (Service: "
    "IoTTwinMaker, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)
_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "iottwinmaker.amazonaws.com"},
         "Action": "sts:AssumeRole"}
    ],
}


def _workspace_resources(bucket, role_name, ws_id):
    """The workspace's bucket, role and Workspace; the twinmaker types take Tags as a map."""
    return {
        "Bucket": {"Type": "AWS::S3::Bucket",
                   "Properties": {"BucketName": bucket,
                                  "Tags": [{"Key": "sim2real-tm", "Value": ws_id}]}},
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST_POLICY,
                "Policies": [{
                    "PolicyName": "s3access",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": ["s3:GetBucket*", "s3:GetObject", "s3:ListBucket",
                                       "s3:PutObject", "s3:DeleteObject"],
                            "Resource": [
                                {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}"},
                                {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}/*"},
                            ],
                        }],
                    },
                }],
                "Tags": [{"Key": "sim2real-tm", "Value": ws_id}],
            },
        },
        "Workspace": {
            "Type": "AWS::IoTTwinMaker::Workspace",
            "DependsOn": ["Role", "Bucket"],
            "Properties": {
                "WorkspaceId": ws_id,
                "Description": "sim2real twinmaker workspace",
                "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                "S3Location": {"Fn::GetAtt": ["Bucket", "Arn"]},
                "Tags": {"sim2real-tm": ws_id},
            },
        },
    }


def _component_type(ct_id, ws_id, is_stored_externally=True):
    return {
        "Type": "AWS::IoTTwinMaker::ComponentType",
        "DependsOn": ["Workspace"],
        "Properties": {
            "WorkspaceId": {"Ref": "Workspace"},
            "ComponentTypeId": ct_id,
            "PropertyDefinitions": {
                "Temperature": {
                    "DataType": {"Type": "DOUBLE"},
                    "IsTimeSeries": True,
                    "IsStoredExternally": is_stored_externally,
                }
            },
            "Tags": {"sim2real-tm": ws_id},
        },
    }


def _pages(fn, key, **kw):
    """Every item under ``key`` across all nextToken pages of ``fn``."""
    items, token = [], None
    while True:
        page = fn(**kw, **({"nextToken": token} if token else {}))
        items += page.get(key, [])
        token = page.get("nextToken")
        if not token:
            return items


def _template(bucket, role_name, ws_id, ct_id, is_stored_externally):
    resources = _workspace_resources(bucket, role_name, ws_id)
    resources["ComponentType"] = _component_type(ct_id, ws_id, is_stored_externally)
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {"ComponentTypeRef": {"Value": {"Ref": "ComponentType"}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation IoTTwinMaker time-series ComponentType not stored externally rolls back.

    IoTTwinMaker refuses the property definition and no component type exists, while the same
    template with IsStoredExternally true deploys a component type that reads back ACTIVE.
    """
    cfn = ctx.client("cloudformation")
    tm = ctx.client("iottwinmaker")
    ok = [ctx.unique_name(f"sim2real-tmneg-ok-{k}-") for k in ("b", "role", "ws", "ct")]
    bad = [ctx.unique_name(f"sim2real-tmneg-bad-{k}-") for k in ("b", "role", "ws", "ct")]

    # Positive control: the same template, the one property given a VALID value.
    ok_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-tmneg-okstack-"),
                         _template(*ok, True), Capabilities=["CAPABILITY_NAMED_IAM"])
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-tmneg-badstack-"),
                          _template(*bad, False), Capabilities=["CAPABILITY_NAMED_IAM"])

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "ComponentType"), ctx.account,
                         *bad)
    assert got == _REJECTED, f"ComponentType reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through IoTTwinMaker, by the component type's id, before any delete.
    gone = ("ResourceNotFoundException", f"Cannot find component type {bad[3]} in workspace "
            f"{bad[2]}.")
    expect_error(lambda: tm.get_component_type(workspaceId=bad[2], componentTypeId=bad[3]), *gone)

    status = wait_stack(cfn, ok_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, ok_id))!r}"
    )
    ref = stack_outputs(cfn, ok_id)["ComponentTypeRef"]
    listed = [c["componentTypeId"] for c in _pages(tm.list_component_types,
                                                    "componentTypeSummaries", workspaceId=ok[2])
              if c["componentTypeId"] == ok[3]]
    assert [f"{ok[2]}|{i}" for i in listed] == [ref], f"control ListComponentTypes {listed!r}"
    ct = tm.get_component_type(workspaceId=ok[2], componentTypeId=ok[3])
    temperature = ct["propertyDefinitions"]["Temperature"]
    assert (ct["status"]["state"], temperature["isTimeSeries"],
            temperature["isStoredExternally"]) == ("ACTIVE", True, True), (
        f"control component type {ct!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
