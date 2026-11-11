"""deploy-kda-studio-application-and-logging-option-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-kda-studio-application-and-logging-option-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue", "iam", "kinesisanalyticsv2", "logs"]

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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


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
_LOG_STREAM = "notebook"
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "kinesisanalytics.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}
_CATALOG_ARN = "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:catalog"
_DB_ARN = "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:database/${GlueDatabase}"
_LOG_GROUP_ARN = "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:${LogGroup}"
# A role created in the same stack may not be assumable yet: KinesisAnalyticsV2 then refuses with
# one of these, and only that refusal is retried with a fresh stack.
_ROLE_PROPAGATION_MARKERS = ("insufficient permission", "sufficient privileges to assume the role")
_ROLE_RETRY_S = 180.0


def _template(role_name, db_name, log_group, app_name, with_option):
    t = [{"Key": "sim2real-kda", "Value": app_name}]
    resources = {
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST,
                "Policies": [{"PolicyName": "studio-access", "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        # glue:GetDatabase authorizes on the catalog AND the database.
                        {"Effect": "Allow", "Action": ["glue:GetDatabase"],
                         "Resource": [{"Fn::Sub": _CATALOG_ARN}, {"Fn::Sub": _DB_ARN}]},
                        {"Effect": "Allow",
                         "Action": ["logs:PutLogEvents", "logs:DescribeLogStreams",
                                    "logs:CreateLogStream"],
                         "Resource": {"Fn::Sub": _LOG_GROUP_ARN + ":*"}},
                    ],
                }}],
                "Tags": t,
            },
        },
        "GlueDatabase": {
            "Type": "AWS::Glue::Database",
            "Properties": {
                "CatalogId": {"Ref": "AWS::AccountId"},
                "DatabaseName": db_name,
                "DatabaseInput": {"Name": db_name, "Description": "sim2real kda studio catalog"},
            },
        },
        "LogGroup": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {"LogGroupName": log_group, "RetentionInDays": 1},
        },
        "LogStream": {
            "Type": "AWS::Logs::LogStream",
            "Properties": {"LogGroupName": {"Ref": "LogGroup"}, "LogStreamName": _LOG_STREAM},
        },
        "Application": {
            "Type": "AWS::KinesisAnalyticsV2::Application",
            "Properties": {
                "ApplicationName": app_name,
                "ApplicationMode": "INTERACTIVE",
                "RuntimeEnvironment": _RUNTIME,
                "ServiceExecutionRole": {"Fn::GetAtt": ["Role", "Arn"]},
                "ApplicationConfiguration": {
                    "ZeppelinApplicationConfiguration": {
                        "CatalogConfiguration": {
                            "GlueDataCatalogConfiguration": {
                                "DatabaseARN": {"Fn::Sub": _DB_ARN},
                            },
                        },
                    },
                },
                "Tags": t,
            },
        },
    }
    outputs = {
        "ApplicationName": {"Value": {"Ref": "Application"}},
        "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
    }
    if with_option:
        resources["LoggingOption"] = {
            "Type": "AWS::KinesisAnalyticsV2::ApplicationCloudWatchLoggingOption",
            "Properties": {
                "ApplicationName": {"Ref": "Application"},
                "CloudWatchLoggingOption": {
                    "LogStreamARN": {"Fn::Sub": _LOG_GROUP_ARN + ":log-stream:" + _LOG_STREAM},
                },
            },
        }
        outputs["LoggingOptionId"] = {"Value": {"Ref": "LoggingOption"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


def _deploy(ctx, cfn, prefix, template):
    """Create the stack until it ends other than with the fresh role's authorization refusal.

    Returns ``(stack_id, stack name)`` of the CREATE_COMPLETE stack.
    """
    deadline = time.monotonic() + _ROLE_RETRY_S
    while True:
        name = ctx.unique_name(prefix)
        stack_id = create_stack(ctx, cfn, name, template, Capabilities=["CAPABILITY_NAMED_IAM"])
        status = wait_stack(cfn, stack_id)
        if status == "CREATE_COMPLETE":
            return stack_id, name
        reason = failed_reason(stack_events(cfn, stack_id), "Application")
        if not any(m in reason for m in _ROLE_PROPAGATION_MARKERS) or time.monotonic() > deadline:
            raise AssertionError(f"stack ended {status!r}: {reason!r}")
        delete_stack(cfn, stack_id)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Studio application and its logging option read back through their services.

    KinesisAnalyticsV2, IAM, Glue and Logs read back every templated property; an update dropping
    the logging option clears it from the same application, and deleting the stack removes it.
    """
    cfn = ctx.client("cloudformation")
    kda = ctx.client("kinesisanalyticsv2")
    iam = ctx.client("iam")
    glue = ctx.client("glue")
    logs = ctx.client("logs")
    role_name = ctx.unique_name("sim2real-kdacfn-role-")
    db_name = ctx.unique_name("sim2real_kdacfn_db_").replace("-", "_")
    log_group = "/aws/kinesis-analytics/" + ctx.unique_name("sim2real-kdacfn-")
    app_name = ctx.unique_name("sim2real-kdacfn-")

    stack_id, stack = _deploy(ctx, cfn, "sim2real-kdacfn-stack-",
                       _template(role_name, db_name, log_group, app_name, True))
    partition = stack_id.split(":")[1]
    out = stack_outputs(cfn, stack_id)

    # Ref against an independent read: the ListApplications entry under the declared name.
    listed = [a["ApplicationName"]
              for a in paginate(kda, "list_applications", "ApplicationSummaries")
              if a["ApplicationName"] == app_name]
    assert listed == [out["ApplicationName"]], f"ListApplications {listed!r} for Ref {out!r}"
    detail = kda.describe_application(ApplicationName=app_name)["ApplicationDetail"]
    role_arn = f"arn:{partition}:iam::{ctx.account}:role/{role_name}"
    db_arn = f"arn:{partition}:glue:{ctx.region}:{ctx.account}:database/{db_name}"
    stream_arn = (f"arn:{partition}:logs:{ctx.region}:{ctx.account}:log-group:{log_group}"
                  f":log-stream:{_LOG_STREAM}")
    catalog = detail["ApplicationConfigurationDescription"][
        "ZeppelinApplicationConfigurationDescription"]["CatalogConfigurationDescription"][
        "GlueDataCatalogConfigurationDescription"]
    got = (detail["ApplicationStatus"], detail["ApplicationMode"], detail["RuntimeEnvironment"],
           detail["ServiceExecutionRole"], catalog)
    want = ("READY", "INTERACTIVE", _RUNTIME, role_arn, {"DatabaseARN": db_arn})
    assert got == want, f"application (status, mode, runtime, role, catalog) {got!r}"
    app_tags = {t["Key"]: t["Value"] for t in kda.list_tags_for_resource(
        ResourceARN=detail["ApplicationARN"])["Tags"] if not t["Key"].startswith("aws:")}
    assert app_tags == {"sim2real": stack, "sim2real-kda": app_name}, f"application tags {app_tags!r}"

    # The logging option: its Ref is the id the application reports, wired to the declared stream.
    opts = [(o.get("CloudWatchLoggingOptionId"), o["LogStreamARN"])
            for o in detail.get("CloudWatchLoggingOptionDescriptions", [])]
    assert opts == [(out["LoggingOptionId"], stream_arn)], (
        f"logging options {opts!r}, expected [({out['LoggingOptionId']!r}, {stream_arn!r})]"
    )

    # The read-only Role GetAtt, the role's trust, inline policy and tags through IAM.
    role = iam.get_role(RoleName=role_name)["Role"]
    assert (out["RoleArn"], role["Arn"]) == (role_arn, role_arn), (
        f"GetAtt Role.Arn {out['RoleArn']!r}, IAM Arn {role['Arn']!r}, expected {role_arn!r}"
    )
    assert role["AssumeRolePolicyDocument"] == _TRUST, f"trust {role['AssumeRolePolicyDocument']!r}"
    inline = iam.get_role_policy(RoleName=role_name, PolicyName="studio-access")["PolicyDocument"]
    assert [s["Resource"] for s in inline["Statement"]] == [
        [f"arn:{partition}:glue:{ctx.region}:{ctx.account}:catalog", db_arn],
        f"arn:{partition}:logs:{ctx.region}:{ctx.account}:log-group:{log_group}:*"], (
        f"inline policy {inline!r}"
    )
    role_tags = {t["Key"]: t["Value"] for t in paginate(iam, "list_role_tags", "Tags",
                                                        RoleName=role_name)}
    assert role_tags == {"sim2real": stack, "sim2real-kda": app_name}, f"role tags {role_tags!r}"

    # The catalog database and the log group / stream through Glue and Logs.
    db = glue.get_database(CatalogId=ctx.account, Name=db_name)["Database"]
    assert (db["Name"], db.get("Description")) == (db_name, "sim2real kda studio catalog"), (
        f"Glue database {db!r}"
    )
    groups = [(g["logGroupName"], g.get("retentionInDays"))
              for g in paginate(logs, "describe_log_groups", "logGroups",
                                logGroupNamePrefix=log_group) if g["logGroupName"] == log_group]
    assert groups == [(log_group, 1)], f"log groups {groups!r}"
    streams = [s["arn"] for s in paginate(logs, "describe_log_streams", "logStreams",
                                          logGroupName=log_group, logStreamNamePrefix=_LOG_STREAM)
               if s["logStreamName"] == _LOG_STREAM]
    assert streams == [stream_arn], f"log streams {streams!r}, expected [{stream_arn!r}]"

    # Child before parent: the update drops only the logging option; the same application
    # (CreateTimestamp) stays READY with no logging option.
    cfn.update_stack(StackName=stack_id, Capabilities=["CAPABILITY_NAMED_IAM"],
                     TemplateBody=_template(role_name, db_name, log_group, app_name, False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"option-removing update ended {status!r}"
    after = kda.describe_application(ApplicationName=app_name)["ApplicationDetail"]
    got = (after["CreateTimestamp"], after["ApplicationStatus"],
           after.get("CloudWatchLoggingOptionDescriptions", []))
    assert got == (detail["CreateTimestamp"], "READY", []), (
        f"after dropping the logging option the application reads {got!r}"
    )

    delete_stack(cfn, stack_id)
    until_raises(lambda: kda.describe_application(ApplicationName=app_name))
    gone = ("ResourceNotFoundException", f"Application '{app_name}' does not exist.")
    expect_error(lambda: kda.describe_application(ApplicationName=app_name), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
