"""cfn-investigation-group-round-trip-then-invalid-rolearn-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-investigation-group-round-trip-then-invalid-rolearn-rejected"
GROUP = "deploy"
SERVICES = ["aiops", "cloudformation"]

# ---- CloudFormation helpers ----

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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "aiops.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_TRANSIENT_HANDLER_REASON = (
    "InvestigationGroup does not exist. (Service: AiOps, Status Code: 404, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "NotFound",
)
_BAD_ROLE_ARN = "tooshort"
_SCHEMA_REJECTION_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)
_NOT_FOUND = ("ResourceNotFoundException", "InvestigationGroup does not exist.")


def _template(name: str, role_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "InvestigationGroup": {
                "Type": "AWS::AIOps::InvestigationGroup",
                "Properties": {
                    "Name": name,
                    "RoleArn": role_arn,
                    "RetentionInDays": 30,
                },
            },
        },
        "Outputs": {
            "GroupRef": {"Value": {"Ref": "InvestigationGroup"}},
            "GroupArn": {"Value": {"Fn::GetAtt": ["InvestigationGroup", "Arn"]}},
            "CreatedBy": {"Value": {"Fn::GetAtt": ["InvestigationGroup", "CreatedBy"]}},
            "CreatedAt": {"Value": {"Fn::GetAtt": ["InvestigationGroup", "CreatedAt"]}},
            "LastModifiedBy": {"Value": {"Fn::GetAtt": ["InvestigationGroup", "LastModifiedBy"]}},
            "LastModifiedAt": {"Value": {"Fn::GetAtt": ["InvestigationGroup", "LastModifiedAt"]}},
        },
    })


def _delete_role(iam, role_name: str) -> None:
    """DeleteRole; only the role's own NoSuchEntity means it was never created."""
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, iam) -> str:
    """A tagged role; its delete is registered before the create."""
    role_name = ctx.unique_name("sim2real-cfres-aiopsrole-")
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )["Role"]["Arn"]


def _create_group_stack(ctx, cf, name: str, role_arn: str, *, timeout_s: float = 180.0) -> str:
    """CreateStack for the minimal investigation-group template, retrying while the handler
    still sees the brand-new role as not-yet-visible (IAM propagation) -- the same transient
    GetInvestigationGroup itself raises right after a role is created. A failure for any other
    reason raises at once."""
    stack_name = ctx.unique_name("sim2real-cfres-igstk-")
    deadline = time.monotonic() + timeout_s
    while True:
        stack_id = create_stack(ctx, cf, stack_name, _template(name, role_arn),
                                Capabilities=["CAPABILITY_IAM"])
        status = wait_stack(cf, stack_id)
        if status == "CREATE_COMPLETE":
            return stack_id
        reason = failed_reason(stack_events(cf, stack_id), "InvestigationGroup")
        delete_stack(cf, stack_id)
        transient = (_HANDLER_REASON.match(reason or "") is not None
                     and handler_reason(reason, ctx.account, name) == _TRANSIENT_HANDLER_REASON)
        if not transient or time.monotonic() > deadline:
            raise AssertionError(f"stack create ended in {status!r}: {reason!r}")
        time.sleep(5.0)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control",
      "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """A deployed AWS::AIOps::InvestigationGroup's Ref, GetAtt attributes and set properties
    match AIOps's own GetInvestigationGroup, and deleting the stack removes it from AIOps; a
    RoleArn too short for the type's own schema is rejected with no group ever created.
    """
    cf = ctx.client("cloudformation")
    iam = ctx.client("iam")
    aiops = ctx.client("aiops")

    existing = paginate(aiops, "list_investigation_groups", "investigationGroups")
    assert existing == [], (
        f"precondition: this singleton check expects no investigation group to exist yet, "
        f"found {existing!r}"
    )

    role_arn = _create_role(ctx, iam)
    name = ctx.unique_name("sim2real-cfres-ig-")

    stack_id = _create_group_stack(ctx, cf, name, role_arn)
    outputs = stack_outputs(cf, stack_id)

    assert outputs["GroupRef"] == outputs["GroupArn"], (
        f"Ref {outputs['GroupRef']!r} != the primary identifier GetAtt Arn {outputs['GroupArn']!r}"
    )

    listed_own = [g for g in paginate(aiops, "list_investigation_groups", "investigationGroups")
                  if g.get("name") == name]
    assert len(listed_own) == 1, f"expected one listed group named {name!r}, got {listed_own!r}"
    assert listed_own[0]["arn"] == outputs["GroupRef"], (
        f"Ref {outputs['GroupRef']!r} != the ListInvestigationGroups arn {listed_own[0]['arn']!r}"
    )

    got = aiops.get_investigation_group(identifier=outputs["GroupRef"])
    assert got["arn"] == outputs["GroupArn"], f"GetAtt Arn != GetInvestigationGroup arn: {got!r}"
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {got['roleArn']!r}"
    assert got["retentionInDays"] == 30, (
        f"expected retentionInDays 30, got {got['retentionInDays']!r}"
    )
    assert outputs["CreatedBy"] == got["createdBy"], (
        f"GetAtt CreatedBy {outputs['CreatedBy']!r} != GetInvestigationGroup createdBy "
        f"{got['createdBy']!r}"
    )
    assert outputs["LastModifiedBy"] == got["lastModifiedBy"], (
        f"GetAtt LastModifiedBy {outputs['LastModifiedBy']!r} != GetInvestigationGroup "
        f"lastModifiedBy {got['lastModifiedBy']!r}"
    )
    assert int(outputs["CreatedAt"]) == got["createdAt"], (
        f"GetAtt CreatedAt {outputs['CreatedAt']!r} != GetInvestigationGroup createdAt "
        f"{got['createdAt']!r}"
    )
    assert int(outputs["LastModifiedAt"]) == got["lastModifiedAt"], (
        f"GetAtt LastModifiedAt {outputs['LastModifiedAt']!r} != GetInvestigationGroup "
        f"lastModifiedAt {got['lastModifiedAt']!r}"
    )

    # The one thing broken: a RoleArn shorter than the type's own 20-character schema minimum.
    # This never reaches AIOps -- CloudFormation's own property validation rejects it before any
    # resource is instantiated, so the control group above is never at risk of being touched.
    bad_name = ctx.unique_name("sim2real-cfres-ig-bad-")
    bad_stack_name = ctx.unique_name("sim2real-cfres-igstk-bad-")
    bad_stack_id = create_stack(ctx, cf, bad_stack_name, _template(bad_name, _BAD_ROLE_ARN),
                                Capabilities=["CAPABILITY_IAM"])

    bad_status = wait_stack(cf, bad_stack_id)
    assert bad_status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {bad_status!r}"
    bad_reason = failed_reason(stack_events(cf, bad_stack_id), bad_stack_name)
    assert bad_reason == _SCHEMA_REJECTION_REASON, (
        f"expected CREATE_FAILED reason {_SCHEMA_REJECTION_REASON!r}, got {bad_reason!r}"
    )

    found = validation_rows(cf, bad_stack_id)
    want = [(
        "InvestigationGroup", "PROPERTY_VALIDATION", "FAILED",
        "FAIL", f"#/RoleArn: expected minLength: 20, actual: {len(_BAD_ROLE_ARN)}",
        "/Resources/InvestigationGroup/Properties/RoleArn",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"

    bad_resources = cf.describe_stack_resources(StackName=bad_stack_id)["StackResources"]
    assert bad_resources == [], (
        f"expected no resource ever instantiated for the rejected stack, got {bad_resources!r}"
    )
    listed = paginate(aiops, "list_investigation_groups", "investigationGroups")
    assert not any(g["name"] == bad_name for g in listed), (
        f"the rejected group's name {bad_name!r} must never appear at AIOps, found {listed!r}"
    )

    # Positive control still stands, untouched by the rejection above.
    still_there = aiops.get_investigation_group(identifier=outputs["GroupRef"])
    assert still_there["arn"] == outputs["GroupArn"], (
        f"control group changed after the rejection: {still_there!r}"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: aiops.get_investigation_group(identifier=outputs["GroupRef"]),
                 *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
