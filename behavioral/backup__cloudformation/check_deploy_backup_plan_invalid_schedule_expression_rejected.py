"""deploy-backup-plan-invalid-schedule-expression-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-backup-plan-invalid-schedule-expression-rejected"
GROUP = "deploy"
SERVICES = ["backup", "cloudformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
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
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
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
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
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
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
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


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError fn() raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----


def _template(vault_name: str, plan_name: str, rule_name: str, schedule: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vault": {
                    "Type": "AWS::Backup::BackupVault",
                    "DeletionPolicy": "Delete",
                    "Properties": {"BackupVaultName": vault_name},
                },
                "Plan": {
                    "Type": "AWS::Backup::BackupPlan",
                    "DependsOn": "Vault",
                    "Properties": {
                        "BackupPlan": {
                            "BackupPlanName": plan_name,
                            "BackupPlanRule": [
                                {
                                    "RuleName": rule_name,
                                    "TargetBackupVault": vault_name,
                                    "ScheduleExpression": schedule,
                                    "StartWindowMinutes": 60,
                                    "CompletionWindowMinutes": 120,
                                }
                            ],
                        },
                    },
                },
            },
            "Outputs": {
                "PlanRef": {"Value": {"Ref": "Plan"}},
                "PlanArn": {"Value": {"Fn::GetAtt": ["Plan", "BackupPlanArn"]}},
            },
        }
    )


_REJECTED = (
    "Error in some rules due to : Cron expression is not valid: Invalid cron expression "
    "(Service: Backup, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS Backup plan with a malformed cron ScheduleExpression is refused by
    AWS Backup and no plan of that name exists, while the same template with a valid cron
    succeeds and its GetAtt BackupPlanArn is the ARN AWS Backup itself reports for the plan."""
    cfn = ctx.client("cloudformation")
    backup = ctx.client("backup")

    # Positive control: a valid cron schedule creates the plan, and GetAtt BackupPlanArn
    # is exactly what AWS Backup itself reports.
    good_vault = ctx.unique_name("sim2real-bkpln-")
    good_plan = ctx.unique_name("sim2real-bkpln-")
    rule_name = "sim2real-daily"
    schedule = "cron(0 5 * * ? *)"
    good_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-bkpln-"),
        _template(good_vault, good_plan, rule_name, schedule),
    )
    status = wait_stack(cfn, good_id, timeout_s=300.0)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    plan_id = out["PlanRef"]
    plan = backup.get_backup_plan(BackupPlanId=plan_id)
    got_arn = plan["BackupPlanArn"]
    assert got_arn == out["PlanArn"], (
        f"GetAtt BackupPlanArn was {out['PlanArn']!r}, AWS Backup reports {got_arn!r}"
    )
    rule = plan["BackupPlan"]["Rules"][0]
    got = (
        plan["BackupPlanId"],
        plan["BackupPlan"]["BackupPlanName"],
        rule["RuleName"],
        rule["TargetBackupVaultName"],
        rule["ScheduleExpression"],
    )
    want = (plan_id, good_plan, rule_name, good_vault, schedule)
    assert got == want, f"AWS Backup reads the control plan as {got!r}, expected {want!r}"

    # Negative: the same shape with a malformed cron expression.
    bad_vault = ctx.unique_name("sim2real-bkpln-")
    bad_plan = ctx.unique_name("sim2real-bkpln-")
    bad_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-bkpln-"),
        _template(bad_vault, bad_plan, rule_name, "not-a-cron"),
    )
    status = wait_stack(cfn, bad_id, timeout_s=300.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Plan"), ctx.account)
    assert got == _REJECTED, f"Plan reason {got!r}, expected {_REJECTED!r}"

    listed = [
        p["BackupPlanName"]
        for p in paginate(backup, "list_backup_plans", "BackupPlansList")
        if p["BackupPlanName"] == bad_plan
    ]
    assert listed == [], f"the rejected plan name {bad_plan!r} must not exist, found {listed!r}"

    delete_stack(cfn, good_id)
    code, message = _error(lambda: backup.get_backup_plan(BackupPlanId=plan_id))
    assert code == "ResourceNotFoundException", code
    assert message == "Failed reading Backup plan with provided version", message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
