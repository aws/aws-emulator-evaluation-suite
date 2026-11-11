"""deploy-amplify-app-and-branch-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-amplify-app-and-branch-round-trip-and-delete"
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

_BRANCH_NAME = "main"
#: The template's own tag; its key differs from the propagated stack tag ``sim2real``.
_TAG_KEY = "sim2real-amp"


def _template(app_name: str, branch_name: str, tag_value: str, *, with_branch: bool = True) -> str:
    t = [{"Key": _TAG_KEY, "Value": tag_value}]
    resources = {
        "App": {
            "Type": "AWS::Amplify::App",
            "Properties": {"Name": app_name, "Tags": t},
        },
    }
    outputs = {
        "AppArn": {"Value": {"Ref": "App"}},
        "AppId": {"Value": {"Fn::GetAtt": ["App", "AppId"]}},
        "AppName": {"Value": {"Fn::GetAtt": ["App", "AppName"]}},
        "AppDefaultDomain": {"Value": {"Fn::GetAtt": ["App", "DefaultDomain"]}},
    }
    if with_branch:
        resources["Branch"] = {
            "Type": "AWS::Amplify::Branch",
            "Properties": {
                "AppId": {"Fn::GetAtt": ["App", "AppId"]},
                "BranchName": branch_name,
                "Tags": t,
            },
        }
        outputs["BranchArn"] = {"Value": {"Ref": "Branch"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Amplify::App and its AWS::Amplify::Branch reach CREATE_COMPLETE with
    their names and tags, their Ref and GetAtt outputs equal Amplify's own values, removing the
    branch from the stack deletes it, and deleting the stack removes the app.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-amplify-app.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-amplify-branch.html
    """
    amp = ctx.client("amplify")
    cf = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-amp-")
    app_name = ctx.unique_name("sim2real-amp-app-")
    branch_gone = ("NotFoundException", f"Branch {_BRANCH_NAME} not found.")
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")

    stack_id = create_stack(ctx, cf, stack, _template(app_name, _BRANCH_NAME, app_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cf, stack_id)
    app_arn, app_id = outputs["AppArn"], outputs["AppId"]
    app_display_name, app_default_domain = outputs["AppName"], outputs["AppDefaultDomain"]
    branch_arn = outputs["BranchArn"]

    # Ref against an independent read: ListApps by the template's name, never a read by the Ref.
    listed = [a["appArn"] for a in paginate(amp, "list_apps", "apps") if a["name"] == app_name]
    assert listed == [app_arn], f"ListApps found {listed!r} for the app named by Ref {app_arn!r}"
    app = amp.get_app(appId=app_id)["app"]
    assert app["appArn"] == app_arn, (
        f"expected Amplify's appArn to equal the stack's Ref {app_arn!r}, got {app['appArn']!r}"
    )
    assert app["appId"] == app_id, (
        f"expected Amplify's appId to equal the GetAtt AppId {app_id!r}, got {app['appId']!r}"
    )
    assert app["name"] == app_name, (
        f"expected Amplify's name to equal the template's Name {app_name!r}, got {app['name']!r}"
    )
    assert app["name"] == app_display_name, (
        f"expected the GetAtt AppName output {app_display_name!r} to equal Amplify's name "
        f"{app['name']!r}"
    )
    assert app["defaultDomain"] == app_default_domain, (
        f"expected Amplify's defaultDomain to equal the GetAtt DefaultDomain output "
        f"{app_default_domain!r}, got {app['defaultDomain']!r}"
    )

    branch = amp.get_branch(appId=app_id, branchName=_BRANCH_NAME)["branch"]
    assert branch["branchArn"] == branch_arn, (
        f"expected Amplify's branchArn to equal the stack's Ref {branch_arn!r}, got "
        f"{branch['branchArn']!r}"
    )
    assert branch["branchName"] == _BRANCH_NAME, (
        f"expected Amplify's branchName to equal the template's BranchName {_BRANCH_NAME!r}, "
        f"got {branch['branchName']!r}"
    )
    # The template's tag, the propagated stack tag and the aws:cloudformation:* tags.
    stack_tags = {_TAG_KEY: app_name, "sim2real": stack, "aws:cloudformation:stack-name": stack,
                  "aws:cloudformation:stack-id": stack_id}
    want_tags = {**stack_tags, "aws:cloudformation:logical-id": "App"}
    assert app.get("tags") == want_tags, f"expected the app's tags {want_tags!r}, got {app.get('tags')!r}"
    want_tags = {**stack_tags, "aws:cloudformation:logical-id": "Branch"}
    assert branch.get("tags") == want_tags, (
        f"expected the branch's tags {want_tags!r}, got {branch.get('tags')!r}"
    )

    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(app_name, _BRANCH_NAME, app_name, with_branch=False),
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected UPDATE_COMPLETE"
    expect_error(lambda: amp.get_branch(appId=app_id, branchName=_BRANCH_NAME), *branch_gone)
    assert amp.get_app(appId=app_id)["app"]["appArn"] == app_arn, (
        "expected the app to survive the branch's removal from the stack"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: cf.describe_stacks(StackName=stack), *stack_gone)
    app_gone = ("NotFoundException", f"App {app_id} not found.")
    expect_error(lambda: amp.get_app(appId=app_id), *app_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
