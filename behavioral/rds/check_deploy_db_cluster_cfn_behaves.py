"""deploy-db-cluster-cfn-behaves."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-db-cluster-cfn-behaves"
GROUP = "deploy"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Aurora DBCluster+DBInstance stack deployed via CloudFormation produces
    a cluster whose writer endpoint/member set resolves to the created instance."""
    cluster_id = ctx.unique_name("sim2real-rds-clu-")
    instance_id = ctx.unique_name("sim2real-rds-cluinst-")
    password = _gen_password()
    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DBCluster:
    Type: AWS::RDS::DBCluster
    DeletionPolicy: Delete
    Properties:
      DBSubnetGroupName: {subnet_group}
      DBClusterIdentifier: {cluster_id}
      Engine: aurora-mysql
      MasterUsername: sim2realadmin
      MasterUserPassword: {password}
      BackupRetentionPeriod: 1
  DBInstance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBInstanceIdentifier: {instance_id}
      Engine: aurora-mysql
      DBInstanceClass: db.t3.medium
      DBClusterIdentifier: !Ref DBCluster
"""
    _deploy_cfn_stack(ctx, template)

    rds = ctx.client("rds")
    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert cluster["Status"] == "available", cluster["Status"]

    members = cluster["DBClusterMembers"]
    assert len(members) == 1, members
    member = members[0]
    assert member["DBInstanceIdentifier"].lower() == instance_id.lower(), member
    assert member["IsClusterWriter"] is True, member

    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert instance["DBInstanceStatus"] == "available", instance["DBInstanceStatus"]
    assert instance["DBClusterIdentifier"].lower() == cluster_id.lower(), instance

    endpoint = cluster["Endpoint"]
    assert endpoint.lower().startswith(cluster_id.lower()), endpoint
    reader_endpoint = cluster.get("ReaderEndpoint", "")
    assert reader_endpoint.lower().startswith(cluster_id.lower()), reader_endpoint


# ===== helpers =====

def _gen_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _deploy_cfn_stack(ctx, template_body: str, timeout_s: int = 1800) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rds-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
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
