"""deploy-amplify-branch-with-unknown-app-id-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-amplify-branch-with-unknown-app-id-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["amplify", "cloudformation"]

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


# ---- Check-specific: the template, then run(). ----

_BRANCH_NAME = "main"
#: The template's own tag; its key differs from the propagated stack tag ``sim2real``.
_TAG_KEY = "sim2real-amp"
_REJECTED = ("Resource of type 'AWS::Amplify::Branch' with identifier 'null' was not found.",
             "NotFound")


def _template(app_name: str, branch_app_id, tag_value: str) -> str:
    """An app and a branch; the control's branch takes the app's GetAtt AppId, the rejected
    stack's branch the one changed property, an AppId no app owns."""
    t = [{"Key": _TAG_KEY, "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "App": {"Type": "AWS::Amplify::App", "Properties": {"Name": app_name, "Tags": t}},
            "Branch": {
                "Type": "AWS::Amplify::Branch",
                "Properties": {
                    "AppId": branch_app_id,
                    "BranchName": _BRANCH_NAME,
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "AppId": {"Value": {"Fn::GetAtt": ["App", "AppId"]}},
            "BranchArn": {"Value": {"Ref": "Branch"}},
        },
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Amplify::Branch naming an AppId no app owns is rejected with
    Amplify's own NotFoundException and the stack rolls back without leaving a branch; the same
    template given its own app's id still succeeds.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-amplify-branch.html
    """
    amp = ctx.client("amplify")
    cf = ctx.client("cloudformation")
    bad_stack = ctx.unique_name("sim2real-ampbadbranch-")
    bad_app_name = ctx.unique_name("sim2real-ampbadbranch-app-")
    # AWS::Amplify::Branch's AppId is constrained to the pattern "d[a-z0-9]+", <= 20 chars, so a
    # value outside that shape never reaches Amplify's API; this one matches the shape but names
    # no app that exists.
    unknown_app_id = ctx.unique_name("d0")

    bad_id = create_stack(ctx, cf, bad_stack,
                          _template(bad_app_name, unknown_app_id, bad_app_name))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    reason = failed_reason(stack_events(cf, bad_id), "Branch")
    got = handler_reason(reason, ctx.account, bad_stack, bad_app_name)
    assert got == _REJECTED, f"expected (message, handler code) {_REJECTED!r}, got {got!r}"

    resources = cf.describe_stack_resources(StackName=bad_id)["StackResources"]
    branch_resources = [r for r in resources if r["ResourceType"] == "AWS::Amplify::Branch"]
    assert len(branch_resources) == 1, (
        f"expected exactly one Branch resource record, got {branch_resources!r}"
    )
    assert branch_resources[0].get("PhysicalResourceId") is None, (
        f"expected the failed Branch to carry no PhysicalResourceId, got "
        f"{branch_resources[0].get('PhysicalResourceId')!r}"
    )
    # Rollback absence through Amplify, before this check deletes the stack: no app by its name.
    left = [a["appArn"] for a in paginate(amp, "list_apps", "apps") if a["name"] == bad_app_name]
    assert left == [], f"the rolled-back stack left apps {left!r} named {bad_app_name!r}"

    delete_stack(cf, bad_id)

    # Positive control: the same template, the branch given its own app's id.
    good_stack = ctx.unique_name("sim2real-ampgoodbranch-")
    app_name = ctx.unique_name("sim2real-ampgoodbranch-app-")
    good_id = create_stack(ctx, cf, good_stack,
                           _template(app_name, {"Fn::GetAtt": ["App", "AppId"]}, app_name))
    good_status = wait_stack(cf, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    good_outputs = stack_outputs(cf, good_id)
    control_branch = amp.get_branch(appId=good_outputs["AppId"], branchName=_BRANCH_NAME)["branch"]
    assert control_branch["branchArn"] == good_outputs["BranchArn"], (
        f"expected the control branch's branchArn to equal the stack's Ref "
        f"{good_outputs['BranchArn']!r}, got {control_branch['branchArn']!r}"
    )
    assert control_branch["branchName"] == _BRANCH_NAME, (
        f"expected the control branch's name {_BRANCH_NAME!r}, got {control_branch['branchName']!r}"
    )
    # The template's tag, the propagated stack tag and the aws:cloudformation:* tags.
    want_tags = {_TAG_KEY: app_name, "sim2real": good_stack,
                 "aws:cloudformation:stack-name": good_stack,
                 "aws:cloudformation:logical-id": "Branch",
                 "aws:cloudformation:stack-id": good_id}
    assert control_branch.get("tags") == want_tags, (
        f"expected the control branch's tags {want_tags!r}, got {control_branch.get('tags')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
