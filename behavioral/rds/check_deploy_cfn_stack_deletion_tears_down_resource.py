"""deploy-cfn-stack-deletion-tears-down-resource."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-cfn-stack-deletion-tears-down-resource"
GROUP = "deploy"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Deleting the CloudFormation stack actually deletes the underlying
    DBInstance such that a subsequent describe returns DBInstanceNotFoundFault,
    not just stack-level DELETE_COMPLETE."""
    instance_id = ctx.unique_name("sim2real-rds-teardown-")
    password = _gen_password()
    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DBInstance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBSubnetGroupName: {subnet_group}
      DBInstanceIdentifier: {instance_id}
      Engine: mysql
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 20
      MasterUsername: sim2realadmin
      MasterUserPassword: {password}
      BackupRetentionPeriod: 0
      PubliclyAccessible: false
"""
    stack_name = _deploy_cfn_stack(ctx, template)

    rds = ctx.client("rds")
    instance = _describe_db_instance(rds, instance_id)
    assert instance["DBInstanceStatus"] == "available", instance["DBInstanceStatus"]

    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_stack_status(ctx, stack_name, {"DELETE_COMPLETE"}, 1800, allow_not_found=True)

    code, message = _client_error(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)
    )
    assert code == "DBInstanceNotFound", code
    assert message == f"DBInstance {instance_id} not found.", message

    reboot_code, reboot_message = _client_error(
        lambda: rds.reboot_db_instance(DBInstanceIdentifier=instance_id)
    )
    assert reboot_code == "DBInstanceNotFound", reboot_code
    assert reboot_message == f"DBInstance not found: {instance_id}", reboot_message


# ===== helpers =====

def _gen_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _client_error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _deploy_cfn_stack(ctx, template_body: str, timeout_s: int = 1800) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rds-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s)
    return stack_name


def _delete_stack(ctx, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; a stack already gone counts as deleted,
    DELETE_FAILED or any other describe error raises."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 850}
    )


def _wait_stack_status(ctx, stack_name, ok_statuses, timeout_s, allow_not_found=False):
    cfn = ctx.client("cloudformation")
    bad_statuses = {
        "CREATE_FAILED", "ROLLBACK_IN_PROGRESS", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
        "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
        "DELETE_FAILED", "UPDATE_FAILED",
    } - set(ok_statuses)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except Exception:
            if allow_not_found:
                return "DELETE_COMPLETE"
            raise
        status = resp["Stacks"][0]["StackStatus"]
        if status in ok_statuses:
            return status
        if status in bad_statuses:
            raise AssertionError(f"stack {stack_name} reached unexpected status {status}")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach {ok_statuses} within {timeout_s}s")


def _describe_db_instance(rds, instance_id):
    return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=100.0, interval_s=2.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
