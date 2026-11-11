"""deploy-rds-cluster-cfn-behavioral."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

import re
import secrets
import string


from behavioral_harness import tags

CHECK = "deploy-rds-cluster-cfn-behavioral"
GROUP = "deploy"
SERVICES = ["rds"]

_TEMPLATE = """
Parameters:
  SubnetIds:
    Type: List<AWS::EC2::Subnet::Id>
  SecurityGroupId:
    Type: AWS::EC2::SecurityGroup::Id
  MasterUsername:
    Type: String
  MasterUserPassword:
    Type: String
    NoEcho: true
Resources:
  SubnetGroup:
    Type: AWS::RDS::DBSubnetGroup
    Properties:
      DBSubnetGroupDescription: sim2real behavioral aurora cluster subnet group
      SubnetIds: !Ref SubnetIds
  Cluster:
    Type: AWS::RDS::DBCluster
    DeletionPolicy: Delete
    Properties:
      Engine: aurora-mysql
      MasterUsername: !Ref MasterUsername
      MasterUserPassword: !Ref MasterUserPassword
      DBSubnetGroupName: !Ref SubnetGroup
      VpcSecurityGroupIds:
        - !Ref SecurityGroupId
      BackupRetentionPeriod: 1
      DeletionProtection: false
  Instance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      Engine: aurora-mysql
      DBInstanceClass: db.t3.medium
      DBClusterIdentifier: !Ref Cluster
Outputs:
  ClusterId:
    Value: !Ref Cluster
  InstanceId:
    Value: !Ref Instance
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed Aurora cluster+instance reaches 'available', exposes a resolvable
    endpoint, and the instance is a real writer member of the cluster (not just
    stack CREATE_COMPLETE)."""
    vpc = _default_vpc_and_subnets(ctx)
    if vpc is None:
        raise AssertionError("no shared network VPC with >=2 subnets available to host the cluster")

    ctx.unique_name("sim2real-cfn-cl-")
    ctx.unique_name("sim2real-cfn-in-")
    password = _rand_password()

    stack_name = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters=[
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(vpc["subnet_ids"])},
            {"ParameterKey": "SecurityGroupId", "ParameterValue": vpc["sg_id"]},
            {"ParameterKey": "MasterUsername", "ParameterValue": "s2radmin"},
            {"ParameterKey": "MasterUserPassword", "ParameterValue": password},
        ],
        timeout_s=2400,
    )
    outputs = _stack_outputs(ctx, stack_name)
    real_cluster_id = outputs["ClusterId"]
    real_instance_id = outputs["InstanceId"]

    rds = ctx.client("rds")
    cluster = rds.describe_db_clusters(DBClusterIdentifier=real_cluster_id)["DBClusters"][0]
    assert cluster["Status"] == "available", f"cluster status was {cluster['Status']!r}"
    endpoint = cluster["Endpoint"]
    assert endpoint and re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", endpoint), f"unexpected endpoint {endpoint!r}"

    instance = rds.describe_db_instances(DBInstanceIdentifier=real_instance_id)["DBInstances"][0]
    assert instance["DBInstanceStatus"] == "available", f"instance status was {instance['DBInstanceStatus']!r}"
    assert instance["DBClusterIdentifier"] == real_cluster_id, (
        f"instance's cluster was {instance['DBClusterIdentifier']!r}, expected {real_cluster_id!r}"
    )

    members = {m["DBInstanceIdentifier"]: m for m in cluster["DBClusterMembers"]}
    assert real_instance_id in members, f"instance not a cluster member: {members.keys()}"
    assert members[real_instance_id]["IsClusterWriter"] is True, (
        f"expected {real_instance_id} to be the writer, got {members[real_instance_id]}"
    )

    # Overly-permissive boundary: creating a SECOND cluster reusing the same identifier must be
    # rejected server-side (not silently accepted / not silently returning the existing cluster).
    import botocore.exceptions

    subnet_group = _network_db_subnet_group(ctx, rds)
    try:
        rds.create_db_cluster(
            DBClusterIdentifier=real_cluster_id,
            Engine="aurora-mysql",
            MasterUsername="s2radmin",
            MasterUserPassword=_rand_password(),
            DBSubnetGroupName=subnet_group,
        )
        raise AssertionError("duplicate CreateDBCluster with an in-use identifier was accepted")
    except botocore.exceptions.ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "DBClusterAlreadyExistsFault", f"unexpected error code {code!r}"
        msg = exc.response["Error"]["Message"]
        assert msg == "DB Cluster already exists", msg

    # Effect-absent: the rejected duplicate must not have altered the original cluster in any way.
    unaffected = rds.describe_db_clusters(DBClusterIdentifier=real_cluster_id)["DBClusters"][0]
    assert unaffected["Engine"] == "aurora-mysql", f"engine changed to {unaffected['Engine']!r}"
    assert unaffected["MasterUsername"] == "s2radmin", (
        f"master username changed to {unaffected['MasterUsername']!r}"
    )
    assert len(unaffected["DBClusterMembers"]) == 1, (
        f"expected exactly 1 member after rejected duplicate, got {unaffected['DBClusterMembers']}"
    )


# ===== helpers =====
def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _default_vpc_and_subnets(ctx) -> dict | None:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    az_to_subnet: dict[str, str] = {}
    for s in subnets:
        az_to_subnet.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(az_to_subnet) < 2:
        return None
    subnet_ids = list(az_to_subnet.values())[:3]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        return None
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sgs[0]["GroupId"]}


def _deploy_cfn(ctx, template_body, parameters=None, timeout_s=1800) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rds-cfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 750}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters or [],
        OnFailure="DELETE",
    )
    ctx.on_cleanup(_cleanup)
    max_attempts = max(int(timeout_s // 30), 10)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts * 30 // 2}
    )
    return stack_name


def _stack_outputs(ctx, stack_name) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
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
