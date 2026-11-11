"""deploy-appintegrations-application-and-event-integration-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appintegrations-application-and-event-integration-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["appintegrations", "cloudformation"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

_SOURCE = "aws.partner/sim2real.example.com/sweep"


def _template(app_name, namespace, access_url, ei_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "App": {
                "Type": "AWS::AppIntegrations::Application",
                "Properties": {
                    "Name": app_name,
                    "Namespace": namespace,
                    "ApplicationSourceConfig": {
                        "ExternalUrlConfig": {"AccessUrl": access_url},
                    },
                    "Tags": [{"Key": "sim2real-app", "Value": app_name}],
                },
            },
            "EventIntegration": {
                "Type": "AWS::AppIntegrations::EventIntegration",
                "Properties": {
                    "Name": ei_name,
                    "EventBridgeBus": "default",
                    "EventFilter": {"Source": "aws.partner/sim2real.example.com/sweep"},
                    "Tags": [{"Key": "sim2real-ei", "Value": ei_name}],
                },
            },
        },
        "Outputs": {
            "AppArn": {"Value": {"Ref": "App"}},
            "AppId": {"Value": {"Fn::GetAtt": ["App", "Id"]}},
            "EiArn": {"Value": {"Fn::GetAtt": ["EventIntegration", "EventIntegrationArn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AppIntegrations Application and EventIntegration read back as templated.

    Ref and GetAtt match independent listings by name, every property and tag reads back, and
    deleting the stack removes both.
    """
    cfn = ctx.client("cloudformation")
    appi = ctx.client("appintegrations")
    stack = ctx.unique_name("sim2real-appint-stack-")
    app_name = ctx.unique_name("sim2real-appint-app-")
    namespace = ctx.unique_name("sim2real-appint-ns-")
    access_url = f"https://example.com/{ctx.unique_name('sim2real-appint-path-')}"
    ei_name = ctx.unique_name("sim2real-appint-ei-")

    stack_id = create_stack(ctx, cfn, stack, _template(app_name, namespace, access_url, ei_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    prefix = f"arn:{partition}:app-integrations:{ctx.region}:{ctx.account}"

    # Ref and GetAtt against independent listings by the templated names.
    apps = [a for a in paginate(appi, "list_applications", "Applications")
            if a["Name"] == app_name]
    assert [(a["Arn"], a["Id"]) for a in apps] == [(out["AppArn"], out["AppId"])], (
        f"ListApplications found {apps!r} for Ref {out['AppArn']!r}"
    )
    app_arn = f"{prefix}:application/{out['AppId']}"
    assert out["AppArn"] == app_arn, f"Ref {out['AppArn']!r} != documented {app_arn!r}"
    eis = [e for e in paginate(appi, "list_event_integrations", "EventIntegrations")
           if e["Name"] == ei_name]
    ei_arn = f"{prefix}:event-integration/{ei_name}"
    assert [e["EventIntegrationArn"] for e in eis] == [ei_arn], (
        f"ListEventIntegrations found {eis!r}, expected {ei_arn!r}"
    )
    assert out["EiArn"] == ei_arn, f"GetAtt EventIntegrationArn {out['EiArn']!r} != {ei_arn!r}"

    # Every templated property and tag through the owning service.
    app = appi.get_application(Arn=app_arn)
    got = (app["Name"], app["Namespace"], app["ApplicationSourceConfig"],
           {k: v for k, v in app.get("Tags", {}).items() if not k.startswith("aws:")})
    want = (app_name, namespace, {"ExternalUrlConfig": {"AccessUrl": access_url}},
            {"sim2real": stack, "sim2real-app": app_name})
    assert got == want, f"GetApplication reads {got!r}, expected {want!r}"
    ei = appi.get_event_integration(Name=ei_name)
    got = (ei["EventIntegrationArn"], ei["EventBridgeBus"], ei["EventFilter"],
           {k: v for k, v in ei.get("Tags", {}).items() if not k.startswith("aws:")})
    want = (ei_arn, "default", {"Source": _SOURCE}, {"sim2real": stack, "sim2real-ei": ei_name})
    assert got == want, f"GetEventIntegration reads {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    app_gone = ("ResourceNotFoundException",
                f"Could not find Application with identifier: {app_arn}.")
    until_raises(lambda: appi.get_application(Arn=app_arn))
    expect_error(lambda: appi.get_application(Arn=app_arn), *app_gone)
    ei_gone = ("ResourceNotFoundException", f"Could not find EventIntegration with name: {ei_name}.")
    until_raises(lambda: appi.get_event_integration(Name=ei_name))
    expect_error(lambda: appi.get_event_integration(Name=ei_name), *ei_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
