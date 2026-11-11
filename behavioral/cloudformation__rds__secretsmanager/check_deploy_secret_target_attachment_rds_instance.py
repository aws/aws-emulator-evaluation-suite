"""deploy-secret-target-attachment-rds-instance."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-secret-target-attachment-rds-instance"
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

_USERNAME = "sim2realadmin"
_EXCLUDED = '"@/'
_PASSWORD_LENGTH = 20
_TAGS = [{"Key": "sim2real", "Value": CHECK}]

def _delete_secret(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise


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


def _template(secret_name: str, instance_id: str, subnet_group: str, *, attach: bool) -> str:
    attachment = """  SecretAttachment:
    Type: AWS::SecretsManager::SecretTargetAttachment
    Properties:
      SecretId: !Ref AppSecret
      TargetId: !Ref DbInstance
      TargetType: AWS::RDS::DBInstance
""" if attach else ""
    attachment_outputs = """  AttachmentRef:
    Value: !Ref SecretAttachment
  AttachmentId:
    Value: !GetAtt SecretAttachment.Id
""" if attach else ""
    return f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AppSecret:
    Type: AWS::SecretsManager::Secret
    DeletionPolicy: Retain
    Properties:
      Name: {secret_name}
      GenerateSecretString:
        SecretStringTemplate: '{{"username":"{_USERNAME}"}}'
        GenerateStringKey: "password"
        ExcludeCharacters: '{_EXCLUDED}'
        PasswordLength: {_PASSWORD_LENGTH}
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
{attachment}Outputs:
  SecretArn:
    Value: !Ref AppSecret
{attachment_outputs}"""


# An RDS instance alone provisions for about five minutes, so this check runs past 300 s.
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A SecretTargetAttachment merges a real RDS instance's connection fields into the secret,
    and removing it by a stack update reverts the secret to its own content while the instance runs.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-secrettargetattachment.html
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")
    sm = ctx.client("secretsmanager")

    net = ctx.network()
    subnet_group = ctx.unique_name("sim2real-sta-sng-")
    ctx.on_cleanup(lambda: _delete_subnet_group(rds, subnet_group))
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=net.subnet_ids,
        Tags=_TAGS,
    )

    instance_id = ctx.unique_name("sim2real-sta-db-")
    stack_name = ctx.unique_name("sim2real-sta-stack-")
    secret_name = ctx.unique_name("sim2real-sta-secret-")
    # The secret is Retain: it outlives the stack, so its own cleanup is registered first.
    ctx.on_cleanup(lambda: _delete_secret(sm, secret_name))
    stack_id = create_stack(ctx, cf, stack_name,
                            _template(secret_name, instance_id, subnet_group, attach=True))
    status = wait_stack(cf, stack_id, timeout_s=1500.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outs = stack_outputs(cf, stack_id)
    secret_arn = outs["SecretArn"]

    listed = [s for s in paginate(sm, "list_secrets", "SecretList",
                                  Filters=[{"Key": "name", "Values": [secret_name]}])
              if s["Name"] == secret_name]
    assert [s["ARN"] for s in listed] == [secret_arn], (
        f"ListSecrets by name returned {len(listed)} secret(s), expected exactly the Secret's Ref"
    )
    assert outs["AttachmentRef"] == secret_arn, (
        f"Ref(SecretAttachment) was {outs['AttachmentRef']!r}, expected the secret ARN {secret_arn!r}"
    )
    assert outs["AttachmentId"] == secret_arn, (
        f"GetAtt SecretAttachment.Id was {outs['AttachmentId']!r}, expected {secret_arn!r}"
    )

    instances = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"]
    assert len(instances) == 1, f"DescribeDBInstances by identifier returned {len(instances)}"
    instance = instances[0]
    seen = (instance["DBInstanceStatus"], instance["Engine"], instance["DBInstanceClass"],
            instance["AllocatedStorage"], instance["BackupRetentionPeriod"],
            instance["PubliclyAccessible"], instance["DBSubnetGroup"]["DBSubnetGroupName"],
            instance["MasterUsername"])
    assert seen == ("available", "mysql", "db.t3.micro", 20, 0, False, subnet_group, _USERNAME), (
        f"the instance read back as {seen!r}"
    )
    endpoint = instance["Endpoint"]

    attached = json.loads(sm.get_secret_value(SecretId=secret_arn)["SecretString"])
    password = attached.get("password", "")
    assert len(password) == _PASSWORD_LENGTH, (
        f"the generated password has {len(password)} characters, expected {_PASSWORD_LENGTH}"
    )
    assert not set(password) & set(_EXCLUDED), (
        "the generated password contains an excluded character"
    )
    expected = {
        "username": _USERNAME, "password": password, "engine": "mysql",
        "host": endpoint["Address"], "port": endpoint["Port"], "dbInstanceIdentifier": instance_id,
    }
    assert attached == expected, (
        f"the attached secret carries keys {sorted(attached)!r} with "
        f"{ {k: v for k, v in attached.items() if k != 'password'}!r}, expected "
        f"{ {k: v for k, v in expected.items() if k != 'password'}!r}"
    )

    # Drop only the attachment; the instance keeps running while its removal is graded.
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(secret_name, instance_id, subnet_group, attach=False),
    )
    status = wait_stack(cf, stack_id, timeout_s=900.0)
    assert status == "UPDATE_COMPLETE", (
        f"the attachment-removing update ended {status!r}: "
        f"{decisive_rows(stack_events(cf, stack_id))!r}"
    )
    still = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"]
    assert [i["DBInstanceStatus"] for i in still] == ["available"], (
        f"the instance after the attachment's removal was {[i['DBInstanceStatus'] for i in still]!r}"
    )
    detached = json.loads(sm.get_secret_value(SecretId=secret_arn)["SecretString"])
    assert detached == {"username": _USERNAME, "password": password}, (
        f"after the attachment's removal the secret carries keys {sorted(detached)!r}, "
        f"expected only ['password', 'username'] with the generated password unchanged"
    )

    # An instance delete outlasts delete_stack's 600 s budget: delete by StackId and wait longer.
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s=1200.0)
    assert status == "DELETE_COMPLETE", (
        f"stack delete ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    instance_not_found = ("DBInstanceNotFound", f"DBInstance {instance_id} not found.")
    expect_error(lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id),
                 *instance_not_found)
    # Retain keeps the secret past the stack delete.
    kept = sm.describe_secret(SecretId=secret_arn)
    assert kept["ARN"] == secret_arn, f"the retained secret described as {kept['ARN']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
