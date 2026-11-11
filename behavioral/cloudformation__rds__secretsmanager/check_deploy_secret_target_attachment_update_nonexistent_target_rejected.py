"""deploy-secret-target-attachment-update-nonexistent-target-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-secret-target-attachment-update-nonexistent-target-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "rds", "secretsmanager"]

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


# ---- Check-specific: the template, then run(). ----

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _delete_subnet_group(rds, name: str, timeout_s: float = 300.0, interval_s: float = 2.0) -> None:
    """Delete a DB subnet group, retrying while a just-deleted instance still references it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.delete_db_subnet_group(DBSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBSubnetGroupNotFoundFault":
                return
            if code != "InvalidDBSubnetGroupStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _template(instance_id: str, subnet_group: str, target_id: str) -> str:
    return f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AppSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      GenerateSecretString:
        SecretStringTemplate: '{{"username":"sim2realadmin"}}'
        GenerateStringKey: "password"
        ExcludeCharacters: '"@/'
        PasswordLength: 20
  DbInstance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBInstanceIdentifier: {instance_id}
      DBSubnetGroupName: {subnet_group}
      Engine: mysql
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 20
      MasterUsername: !Sub "{{{{resolve:secretsmanager:${{AppSecret}}:SecretString:username}}}}"
      MasterUserPassword: !Sub "{{{{resolve:secretsmanager:${{AppSecret}}:SecretString:password}}}}"
      BackupRetentionPeriod: 0
      PubliclyAccessible: false
  SecretAttachment:
    Type: AWS::SecretsManager::SecretTargetAttachment
    Properties:
      SecretId: !Ref AppSecret
      TargetId: {target_id}
      TargetType: AWS::RDS::DBInstance
Outputs:
  SecretArn:
    Value: !Ref AppSecret
"""


# An RDS instance alone provisions for about five minutes, so this check runs past 300 s.
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A SecretTargetAttachment update that retargets a nonexistent RDS instance is rejected,
    the stack rolls back, and the secret keeps its originally attached host/port/engine.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-secrettargetattachment.html
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")
    sm = ctx.client("secretsmanager")

    net = ctx.network()
    subnet_group = ctx.unique_name("sim2real-stau-sng-")
    ctx.on_cleanup(lambda: _delete_subnet_group(rds, subnet_group))
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=net.subnet_ids,
        Tags=_TAGS,
    )

    instance_id = ctx.unique_name("sim2real-stau-db-")
    stack_name = ctx.unique_name("sim2real-stau-stack-")

    stack_id = create_stack(ctx, cf, stack_name,
                            _template(instance_id, subnet_group, "!Ref DbInstance"))
    status = wait_stack(cf, stack_id, timeout_s=1500.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    secret_arn = stack_outputs(cf, stack_id)["SecretArn"]

    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    endpoint = instance["Endpoint"]
    created_at = instance["InstanceCreateTime"]
    before = json.loads(sm.get_secret_value(SecretId=secret_arn)["SecretString"])
    attached = {k: before.get(k) for k in ("host", "port", "engine", "dbInstanceIdentifier",
                                            "username")}
    want = {"host": endpoint["Address"], "port": endpoint["Port"], "engine": "mysql",
            "dbInstanceIdentifier": instance_id, "username": "sim2realadmin"}
    assert attached == want, (
        f"positive control: the attached secret fields were {attached!r}, expected {want!r}"
    )

    bad_target = ctx.unique_name("sim2real-stau-missing-")
    cf.update_stack(StackName=stack_id, TemplateBody=_template(instance_id, subnet_group, bad_target))
    status = wait_stack(cf, stack_id, timeout_s=900.0)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"the retargeting update ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    rejected = (
        f"DBInstance {bad_target} not found. "
        "(Service: Rds, Status Code: 404, Request ID: <id>) (SDK Attempt Count: <n>)",
        "NotFound",
    )
    got = handler_reason(failed_reason(stack_events(cf, stack_id), "SecretAttachment",
                                       "UPDATE_FAILED"), ctx.account)
    assert got == rejected, f"SecretAttachment UPDATE_FAILED reason {got!r}, expected {rejected!r}"

    after = json.loads(sm.get_secret_value(SecretId=secret_arn)["SecretString"])
    assert after.get("host") == endpoint["Address"], (
        f"the rejected update changed the attached host to {after.get('host')!r}, "
        f"expected it to stay {endpoint['Address']!r}"
    )
    assert after == before, (
        f"the secret content changed across a rejected update: keys {sorted(after)!r} vs "
        f"{sorted(before)!r}"
    )
    # The same instance, not a replacement, is still the attachment's target.
    now = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert now["InstanceCreateTime"] == created_at, (
        f"the instance was re-created across the rejected update: {now['InstanceCreateTime']!r} "
        f"!= {created_at!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
