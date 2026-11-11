"""deploy-kda-streaming-mode-on-zeppelin-runtime-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-kda-streaming-mode-on-zeppelin-runtime-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "kinesisanalyticsv2"]

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

_RUNTIME = "ZEPPELIN-FLINK-3_0"
_REJECTED = (
    "Invalid configuration provided. ApplicationMode 'STREAMING' is not applicable to runtime "
    f"environment : {_RUNTIME} (Service: KinesisAnalyticsV2, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)
# A role created in the same stack may not be assumable yet: KinesisAnalyticsV2 then refuses with
# one of these, and only that refusal is retried with a fresh stack.
_ROLE_PROPAGATION_MARKERS = ("insufficient permission", "sufficient privileges to assume the role")
_ROLE_RETRY_S = 180.0


def _template(role_name, db_name, app_name, mode):
    t = [{"Key": "sim2real-kda", "Value": app_name}]
    catalog_arn = "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:catalog"
    db_arn = "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/${GlueDatabase}"
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "kinesisanalytics.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{"PolicyName": "studio-access", "PolicyDocument": {
                        "Version": "2012-10-17",
                        # glue:GetDatabase authorizes on the catalog AND the database.
                        "Statement": [{"Effect": "Allow", "Action": ["glue:GetDatabase"],
                                       "Resource": [{"Fn::Sub": catalog_arn},
                                                    {"Fn::Sub": db_arn}]}],
                    }}],
                    "Tags": t,
                },
            },
            "GlueDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseName": db_name,
                    "DatabaseInput": {"Name": db_name},
                },
            },
            "Application": {
                "Type": "AWS::KinesisAnalyticsV2::Application",
                "Properties": {
                    "ApplicationName": app_name,
                    "ApplicationMode": mode,
                    "RuntimeEnvironment": _RUNTIME,
                    "ServiceExecutionRole": {"Fn::GetAtt": ["Role", "Arn"]},
                    "ApplicationConfiguration": {
                        "ZeppelinApplicationConfiguration": {
                            "CatalogConfiguration": {
                                "GlueDataCatalogConfiguration": {
                                    "DatabaseARN": {"Fn::Sub": db_arn},
                                },
                            },
                        },
                    },
                    "Tags": t,
                },
            },
        },
        "Outputs": {"ApplicationName": {"Value": {"Ref": "Application"}}},
    })


def _deploy(ctx, cfn, prefix, template):
    """Create the stack until it ends other than with the fresh role's authorization refusal.

    Returns ``(stack_id, status, reason)``: the Application's CREATE_FAILED reason, or None.
    """
    deadline = time.monotonic() + _ROLE_RETRY_S
    while True:
        stack_id = create_stack(ctx, cfn, ctx.unique_name(prefix), template,
                                Capabilities=["CAPABILITY_NAMED_IAM"])
        status = wait_stack(cfn, stack_id)
        if status == "CREATE_COMPLETE":
            return stack_id, status, None
        reason = failed_reason(stack_events(cfn, stack_id), "Application")
        if not any(m in reason for m in _ROLE_PROPAGATION_MARKERS) or time.monotonic() > deadline:
            return stack_id, status, reason
        delete_stack(cfn, stack_id)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Zeppelin-runtime KinesisAnalyticsV2 application in STREAMING mode rolls back.

    KinesisAnalyticsV2 refuses the mode and lists no application, while the same template in
    INTERACTIVE mode deploys an application that reads back READY with its templated settings.
    """
    cfn = ctx.client("cloudformation")
    kda = ctx.client("kinesisanalyticsv2")
    ok_role = ctx.unique_name("sim2real-kdabadmode-ok-role-")
    ok_db = ctx.unique_name("sim2real_kdabadmode_ok_db_").replace("-", "_")
    ok_app = ctx.unique_name("sim2real-kdabadmode-ok-")
    bad_role = ctx.unique_name("sim2real-kdabadmode-bad-role-")
    bad_db = ctx.unique_name("sim2real_kdabadmode_bad_db_").replace("-", "_")
    bad_app = ctx.unique_name("sim2real-kdabadmode-bad-")

    # Positive control: the same template with ApplicationMode given a VALID value.
    ok_id, status, reason = _deploy(ctx, cfn, "sim2real-kdabadmode-okstack-",
                                    _template(ok_role, ok_db, ok_app, "INTERACTIVE"))
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}: {reason!r}"
    partition = ok_id.split(":")[1]
    ref = stack_outputs(cfn, ok_id)["ApplicationName"]
    listed = [a for a in paginate(kda, "list_applications", "ApplicationSummaries")
              if a["ApplicationName"] in (ok_app, bad_app)]
    assert [(a["ApplicationName"], a["ApplicationMode"]) for a in listed] == [
        (ref, "INTERACTIVE")], f"ListApplications entries {listed!r} for Ref {ref!r}"
    detail = kda.describe_application(ApplicationName=ok_app)["ApplicationDetail"]
    db_arn = f"arn:{partition}:glue:{ctx.region}:{ctx.account}:database/{ok_db}"
    catalog = detail["ApplicationConfigurationDescription"][
        "ZeppelinApplicationConfigurationDescription"]["CatalogConfigurationDescription"][
        "GlueDataCatalogConfigurationDescription"]
    got = (detail["ApplicationStatus"], detail["ApplicationMode"], detail["RuntimeEnvironment"],
           detail["ServiceExecutionRole"], catalog)
    want = ("READY", "INTERACTIVE", _RUNTIME, f"arn:{partition}:iam::{ctx.account}:role/{ok_role}",
            {"DatabaseARN": db_arn})
    assert got == want, f"control (status, mode, runtime, role, catalog) {got!r}"

    # The rejected stack: only ApplicationMode differs.
    bad_id, status, reason = _deploy(ctx, cfn, "sim2real-kdabadmode-badstack-",
                                     _template(bad_role, bad_db, bad_app, "STREAMING"))
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(reason, ctx.account, bad_app)
    assert got == _REJECTED, f"Application reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through KinesisAnalyticsV2, by the name the application would have had.
    listed = [a["ApplicationName"]
              for a in paginate(kda, "list_applications", "ApplicationSummaries")
              if a["ApplicationName"] == bad_app]
    assert listed == [], f"the rolled-back application is listed: {listed!r}"
    gone = ("ResourceNotFoundException", f"Application '{bad_app}' does not exist.")
    expect_error(lambda: kda.describe_application(ApplicationName=bad_app), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
