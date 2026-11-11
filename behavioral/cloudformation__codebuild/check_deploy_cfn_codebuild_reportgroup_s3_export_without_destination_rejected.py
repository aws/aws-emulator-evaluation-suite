"""deploy-cfn-codebuild-reportgroup-s3-export-without-destination-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-codebuild-reportgroup-s3-export-without-destination-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "codebuild"]

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

_REJECTED = (
    "S3 export config is required when export config type is S3 (Service: CodeBuild, "
    "Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
def _template(report_group_name: str, export_config: dict) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ReportGroup": {
                    "Type": "AWS::CodeBuild::ReportGroup",
                    "Properties": {
                        "Name": report_group_name,
                        "Type": "TEST",
                        "ExportConfig": export_config,
                        "DeleteReports": True,
                    },
                },
            },
        }
    )


@tags(
    "axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control",
)
def run(ctx) -> None:
    """An AWS::CodeBuild::ReportGroup with ExportConfigType S3 and no S3Destination fails
    with CodeBuild's error and is never created, while the same template exporting
    NO_EXPORT deploys."""
    cf = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")

    good_name = ctx.unique_name("sim2real-behav-cfnok-")
    bad_name = ctx.unique_name("sim2real-behav-cfnbad-")
    good_stack = ctx.unique_name("sim2real-behav-stack-ok-")
    bad_stack = ctx.unique_name("sim2real-behav-stack-bad-")

    # Positive control: the identical shape with a valid export config, through CloudFormation.
    good_id = create_stack(ctx, cf, good_stack, _template(good_name, {"ExportConfigType": "NO_EXPORT"}),
                           DisableRollback=True)
    status = wait_stack(cf, good_id, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    partition = good_id.split(":")[1]
    batch_resp = codebuild.batch_get_report_groups(reportGroupArns=[_arn(cf, good_id)])
    assert batch_resp["reportGroupsNotFound"] == [], (
        f"positive control: expected the report group found, got not-found "
        f"{batch_resp['reportGroupsNotFound']!r}"
    )
    assert len(batch_resp["reportGroups"]) == 1, (
        f"positive control: expected one report group, got {len(batch_resp['reportGroups'])}"
    )
    control = batch_resp["reportGroups"][0]
    got_control = (control["name"], control["type"], control["exportConfig"]["exportConfigType"])
    assert got_control == (good_name, "TEST", "NO_EXPORT"), (
        f"positive control report group: expected {(good_name, 'TEST', 'NO_EXPORT')!r}, got {got_control!r}"
    )

    # The one thing broken: ExportConfigType S3 with no S3Destination.
    bad_id = create_stack(ctx, cf, bad_stack, _template(bad_name, {"ExportConfigType": "S3"}),
                          DisableRollback=True)
    status = wait_stack(cf, bad_id, timeout_s=180.0)
    assert status == "CREATE_FAILED", f"expected stack status CREATE_FAILED, got {status!r}"
    reason = failed_reason(stack_events(cf, bad_id), "ReportGroup")
    got_error = handler_reason(reason, ctx.account, bad_stack, bad_name)
    assert got_error == _REJECTED, f"CREATE_FAILED reason: expected {_REJECTED!r}, got {got_error!r}"

    bad_resp = codebuild.batch_get_report_groups(
        reportGroupArns=[_candidate_arn(ctx, partition, bad_name)])
    assert bad_resp["reportGroups"] == [], (
        f"the invalid-export-config report group {bad_name!r} was minted anyway: {bad_resp['reportGroups']}"
    )
    assert bad_resp["reportGroupsNotFound"] == [_candidate_arn(ctx, partition, bad_name)], (
        f"expected the candidate arn in reportGroupsNotFound, got {bad_resp['reportGroupsNotFound']!r}"
    )

    good_arn = _arn(cf, good_id)
    for stack_name, stack_id in ((bad_stack, bad_id), (good_stack, good_id)):
        delete_stack(cf, stack_id)
        stack_gone = ("ValidationError", f"Stack with id {stack_name} does not exist")
        expect_error(lambda stack_name=stack_name: cf.describe_stacks(StackName=stack_name),
                     *stack_gone)

    after = codebuild.batch_get_report_groups(reportGroupArns=[good_arn])
    assert after["reportGroups"] == [] and after["reportGroupsNotFound"] == [good_arn], (
        f"the control report group must be gone after its stack delete: {after!r}"
    )


def _candidate_arn(ctx, partition: str, name: str) -> str:
    """The arn a successfully created report group of this name would carry."""
    return f"arn:{partition}:codebuild:{ctx.region}:{ctx.account}:report-group/{name}"


def _arn(cf, stack_id: str) -> str:
    """The physical id (arn) of the stack's ReportGroup resource."""
    return cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="ReportGroup")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
