"""deploy-cfn-serverlessrepo-application-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-serverlessrepo-application-round-trip-and-delete"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "serverlessrepo"]

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

def _find_by_name(sar, name: str, *, timeout_s=60.0, interval_s=3.0):
    """Poll ListApplications for the entry named *name*; the list lags CreateApplication briefly."""
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        last = [a for a in paginate(sar, "list_applications", "Applications") if a["Name"] == name]
        if last:
            return last[0]
        time.sleep(interval_s)
    raise AssertionError(f"ListApplications never showed {name!r} within {timeout_s}s (last={last!r})")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ServerlessRepo::Application is a real SAR application: Ref
    is its ApplicationId ARN, its GetAtt CreationTime matches SAR's own, and every declared
    property reads back through GetApplication. Deleting the stack removes it from SAR too.
    """
    cfn = ctx.client("cloudformation")
    sar = ctx.client("serverlessrepo")

    stack_name = ctx.unique_name("sim2real-behav-cfn-sarapp-")
    app_name = ctx.unique_name("sim2real-behav-sarapp-")
    author = ctx.unique_name("sim2real-behav-author-")
    description = "sim2real behavioral check: cloudformation-provisioned SAR application"

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "App": {
                "Type": "AWS::ServerlessRepo::Application",
                "Properties": {
                    "Name": app_name,
                    "Author": author,
                    "Description": description,
                    "SpdxLicenseId": "Apache-2.0",
                },
            },
        },
        "Outputs": {
            "AppRef": {"Value": {"Ref": "App"}},
            # IsVerifiedAuthor is a boolean read-only attribute; CloudFormation's Outputs
            # require a string Value, so only the string-typed GetAtt (CreationTime) can be
            # exported here. IsVerifiedAuthor is read back directly through SAR below instead.
            "AppCreationTime": {"Value": {"Fn::GetAtt": ["App", "CreationTime"]}},
        },
    })

    stack_id = create_stack(ctx, cfn, stack_name, template)
    created = wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {created!r}"

    outputs = stack_outputs(cfn, stack_id)
    ref = outputs["AppRef"]

    # ---- Ref == the primary identifier, proven by an independent read (ListApplications by
    # the name the template declared), never by feeding Ref back into GetApplication.
    summary = _find_by_name(sar, app_name)
    assert ref == summary["ApplicationId"], (
        f"Ref was {ref!r}, ListApplications' own ApplicationId for {app_name!r} is "
        f"{summary['ApplicationId']!r}"
    )
    assert summary["Author"] == author, f"expected Author {author!r}, got {summary['Author']!r}"
    assert summary["Description"] == description, (
        f"expected Description {description!r}, got {summary['Description']!r}"
    )
    assert summary["SpdxLicenseId"] == "Apache-2.0", (
        f"expected SpdxLicenseId 'Apache-2.0', got {summary['SpdxLicenseId']!r}"
    )

    # ---- GetAtt CreationTime matches SAR's own GetApplication value.
    got = sar.get_application(ApplicationId=ref)
    assert outputs["AppCreationTime"] == got["CreationTime"], (
        f"GetAtt App.CreationTime was {outputs['AppCreationTime']!r}, "
        f"GetApplication's own CreationTime is {got['CreationTime']!r}"
    )
    assert got["IsVerifiedAuthor"] is False, (
        f"expected IsVerifiedAuthor False for a freshly-created application, got "
        f"{got['IsVerifiedAuthor']!r}"
    )
    assert got["Name"] == app_name, f"expected Name {app_name!r}, got {got['Name']!r}"
    assert got["Author"] == author, f"expected Author {author!r}, got {got['Author']!r}"
    assert got["Description"] == description, (
        f"expected Description {description!r}, got {got['Description']!r}"
    )
    assert got["SpdxLicenseId"] == "Apache-2.0", (
        f"expected SpdxLicenseId 'Apache-2.0', got {got['SpdxLicenseId']!r}"
    )

    delete_stack(cfn, stack_id)
    gone = ("NotFoundException", f"Application with id {ref} could not be found.")
    expect_error(lambda: sar.get_application(ApplicationId=ref), *gone)

    remaining = [a for a in paginate(sar, "list_applications", "Applications") if a["Name"] == app_name]
    assert remaining == [], f"ListApplications still shows {app_name!r} after stack delete: {remaining!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
