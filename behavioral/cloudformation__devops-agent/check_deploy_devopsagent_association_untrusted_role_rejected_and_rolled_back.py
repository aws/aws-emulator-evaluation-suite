"""deploy-devopsagent-association-untrusted-role-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-devopsagent-association-untrusted-role-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "devops-agent"]

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

_EXAMPLE_ACCOUNT = "111122223333"  # the documented example account, trusted instead of our own
_REJECTED = (
    "Error occurred during operation 'AWS::DevOpsAgent::Association: Invalid STS role "
    "configuration for session monitorVerificationAssociationRoleSession. Verify the role's "
    "trust policy. (Service: DevOpsAgent, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)'.",
    "GeneralServiceException",
)


def _role(role_name, source_account, space_arn=None):
    condition = {"StringEquals": {"aws:SourceAccount": source_account}}
    if space_arn is not None:
        condition["ArnLike"] = {"aws:SourceArn": space_arn}
    return {"Type": "AWS::IAM::Role", "Properties": {
        "RoleName": role_name,
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "aidevops.amazonaws.com"},
                           "Action": "sts:AssumeRole", "Condition": condition}],
        },
        "ManagedPolicyArns": [
            {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AIDevOpsAgentAccessPolicy"}],
    }}


def _template(space_name, role_name, source_account):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Space": {"Type": "AWS::DevOpsAgent::AgentSpace", "Properties": {
                "Name": space_name, "Tags": [{"Key": "sim2real-space", "Value": space_name}],
            }},
            "AssocRole": _role(role_name, source_account),
            "Association": {"Type": "AWS::DevOpsAgent::Association", "Properties": {
                "AgentSpaceId": {"Ref": "Space"},
                "ServiceId": "aws",
                "Configuration": {"Aws": {
                    "AccountId": {"Ref": "AWS::AccountId"},
                    "AccountType": "monitor",
                    "AssumableRoleArn": {"Fn::GetAtt": "AssocRole.Arn"},
                }},
            }},
        },
        "Outputs": {
            "AgentSpaceId": {"Value": {"Ref": "Space"}},
            "AssociationId": {"Value": {"Fn::GetAtt": "Association.AssociationId"}},
        },
    })


def _space_ids(devops, name):
    """The ids of every agent space named ``name``, across all ListAgentSpaces pages."""
    return [s["agentSpaceId"] for s in paginate(devops, "list_agent_spaces", "agentSpaces")
            if s["name"] == name]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DevOps Agent Association whose role trusts another account is refused by
    DevOps Agent's STS role validation and its space rolls back away, while the same template
    with the role trusting this account associates.
    """
    devops = ctx.client("devops-agent")
    cfn = ctx.client("cloudformation")
    bad_space = ctx.unique_name("sim2real-devopsagentassocbad-space-")
    good_space = ctx.unique_name("sim2real-devopsagentassocgood-space-")

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-devopsagentassocbad-"),
                          _template(bad_space, ctx.unique_name("sim2real-devopsagentassocbad-role-"),
                                    _EXAMPLE_ACCOUNT),
                          Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    events = stack_events(cfn, bad_id)
    got = handler_reason(failed_reason(events, "Association"), ctx.account)
    assert got == _REJECTED, f"Association reason {got!r}, expected {_REJECTED!r}"
    space_ids = {e["PhysicalResourceId"] for e in events
                 if e["LogicalResourceId"] == "Space" and e["ResourceStatus"] == "CREATE_COMPLETE"}
    assert len(space_ids) == 1, f"Space CREATE_COMPLETE rows name {space_ids!r}"
    space_id = space_ids.pop()

    # Rollback absence through DevOps Agent, BEFORE this check's own delete.
    assert _space_ids(devops, bad_space) == [], f"the rolled-back space {bad_space!r} is listed"
    refused = ("ResourceNotFoundException", f"AgentSpace with agentSpaceId {space_id} not found.")
    expect_error(lambda: devops.get_agent_space(agentSpaceId=space_id), *refused)

    # Positive control: the same template with the role trusting this account.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-devopsagentassocgood-"),
                           _template(good_space,
                                     ctx.unique_name("sim2real-devopsagentassocgood-role-"),
                                     ctx.account),
                           Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    assert _space_ids(devops, good_space) == [out["AgentSpaceId"]], f"control space {good_space!r}"
    assocs = paginate(devops, "list_associations", "associations",
                      agentSpaceId=out["AgentSpaceId"])
    got = [(a["associationId"], a["serviceId"], a["status"]) for a in assocs]
    assert got == [(out["AssociationId"], "aws", "valid")], f"control associations {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
