"""deploy-rds-proxy-cfn-routes-to-target."""
from __future__ import annotations

import json
import secrets
import string
import time


from behavioral_harness import tags

CHECK = "deploy-rds-proxy-cfn-routes-to-target"
GROUP = "deploy"
SERVICES = ["rds"]

_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]

_TEMPLATE = """
Parameters:
  DBProxyName:
    Type: String
  RoleArn:
    Type: String
  SubnetIds:
    Type: List<AWS::EC2::Subnet::Id>
  SecurityGroupId:
    Type: AWS::EC2::SecurityGroup::Id
  SecretArn:
    Type: String
  DBInstanceIdentifier:
    Type: String
Resources:
  Proxy:
    Type: AWS::RDS::DBProxy
    Properties:
      DBProxyName: !Ref DBProxyName
      EngineFamily: MYSQL
      RoleArn: !Ref RoleArn
      VpcSubnetIds: !Ref SubnetIds
      VpcSecurityGroupIds:
        - !Ref SecurityGroupId
      RequireTLS: false
      Auth:
        - AuthScheme: SECRETS
          IAMAuth: DISABLED
          SecretArn: !Ref SecretArn
  TargetGroup:
    Type: AWS::RDS::DBProxyTargetGroup
    Properties:
      DBProxyName: !Ref Proxy
      TargetGroupName: default
      DBInstanceIdentifiers:
        - !Ref DBInstanceIdentifier
Outputs:
  ProxyName:
    Value: !Ref Proxy
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed DBProxy registers its backing instance as a healthy target.

    The default target group is available and DescribeDBProxyTargets reports the instance as an
    RDS_INSTANCE target with TargetHealth AVAILABLE; no connection is made through the proxy.
    """
    rds = ctx.client("rds")
    vpc = _own_private_network(ctx)
    iam = ctx.client("iam")
    sm = ctx.client("secretsmanager")

    password = _rand_password()
    instance_id = ctx.unique_name("sim2real-proxytgt-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        DBSubnetGroupName=vpc["subnet_group"],
        VpcSecurityGroupIds=[vpc["sg_id"]],
        PubliclyAccessible=False,
        BackupRetentionPeriod=0,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id))

    secret_arn = sm.create_secret(
        Name=ctx.unique_name("sim2real-proxy-secret-"),
        SecretString=json.dumps({"username": "s2radmin", "password": password}),
        Tags=_MANAGED_TAGS,
    )["ARN"]
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    role_name = ctx.unique_name("sim2real-proxy-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue"],
                "Resource": secret_arn,
            },
            {
                # RDS Proxy must decrypt the secret via the account's default
                # aws/secretsmanager KMS key; without this the proxy's target/secret
                # validation fails and the stack rolls back.
                "Effect": "Allow",
                "Action": ["kms:Decrypt"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"kms:ViaService": f"secretsmanager.{ctx.region}.amazonaws.com"}
                },
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="secrets-access", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="secrets-access"))

    from botocore.exceptions import WaiterError

    try:
        rds.get_waiter("db_instance_available").wait(
            DBInstanceIdentifier=instance_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 1800) // 2))},
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(f"instance {instance_id} available: the run budget ended first; not graded") from exc
        raise

    # IAM role/policy propagation to RDS is eventually consistent: a proxy create can fail
    # on the first attempt even after the role exists. Retry the deploy itself, bounded, rather
    # than guessing a wait long enough to cover it.
    deploy_deadline = time.monotonic() + _budget_s(ctx, 180)
    stack_name = None
    while stack_name is None:
        try:
            stack_name = _deploy_cfn(
                ctx,
                _TEMPLATE,
                parameters=[
                    {
                        "ParameterKey": "DBProxyName",
                        "ParameterValue": ctx.unique_name("sim2real-proxy-"),
                    },
                    {"ParameterKey": "RoleArn", "ParameterValue": role_arn},
                    {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(vpc["subnet_ids"])},
                    {"ParameterKey": "SecurityGroupId", "ParameterValue": vpc["sg_id"]},
                    {"ParameterKey": "SecretArn", "ParameterValue": secret_arn},
                    {"ParameterKey": "DBInstanceIdentifier", "ParameterValue": instance_id},
                ],
                timeout_s=_budget_s(ctx, 1200),
            )
        except _StackCreateFailed as exc:
            if time.monotonic() >= deploy_deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("proxy stack CREATE_COMPLETE: the run budget ended first; not graded") from exc
                raise AssertionError(
                    "proxy stack repeatedly failed to create, most recently: "
                    f"{exc}; likely the IAM role has not finished propagating for RDS to assume it"
                ) from exc
            time.sleep(2)
    outputs = _stack_outputs(ctx, stack_name)
    proxy_name = outputs["ProxyName"]

    tg = rds.describe_db_proxy_target_groups(DBProxyName=proxy_name)["TargetGroups"][0]
    assert tg["Status"] == "available", f"target group status was {tg['Status']!r}"

    deadline = time.monotonic() + _budget_s(ctx, 600)
    target = None
    while time.monotonic() < deadline:
        targets = rds.describe_db_proxy_targets(DBProxyName=proxy_name)["Targets"]
        matches = [t for t in targets if t.get("RdsResourceId") == instance_id]
        if matches and matches[0]["TargetHealth"]["State"] == "AVAILABLE":
            target = matches[0]
            break
        time.sleep(2)
    if target is None and _budget_spent(ctx):
        raise TimeoutError("proxy target AVAILABLE health: the run budget ended first; not graded")
    assert target is not None, "proxy target never reported AVAILABLE health"
    assert target["Type"] == "RDS_INSTANCE", f"target type was {target['Type']!r}, expected RDS_INSTANCE"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


class _StackCreateFailed(Exception):
    """The proxy stack did not reach CREATE_COMPLETE; the only failure the deploy loop retries."""


_RETRY_CODES = ("DependencyViolation", "InvalidGroup.InUse")


def _own_private_network(ctx) -> dict:
    """A VPC this check creates, with a subnet in each of two AZs, a DB subnet group and an SG
    admitting MySQL from itself, shared by the instance and the proxy; all registered for cleanup."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    ec2_tags = [{"Key": t["Key"], "Value": t["Value"]} for t in _MANAGED_TAGS]
    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required"]}]
        )["AvailabilityZones"]
        if z["State"] == "available"
    )
    assert len(azs) >= 2, f"region {ctx.region!r} has only {len(azs)} available AZ(s); need 2"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.81.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": ec2_tags}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.81.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": ec2_tags}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _drop_subnet(ec2, sid))
        subnet_ids.append(sid)
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-proxy-sg-"),
        Description="sim2real rds proxy check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": ec2_tags}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
            "UserIdGroupPairs": [{"GroupId": sg_id}],
        }],
    )
    group_name = ctx.unique_name("sim2real-proxy-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=group_name, DBSubnetGroupDescription="sim2real rds proxy check",
        SubnetIds=subnet_ids, Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=group_name))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id, "subnet_group": group_name}


def _drop_subnet(ec2, subnet_id: str, timeout_s: float = 900) -> None:
    """Teardown: wait out the RDS and proxy ENIs left in the subnet, then delete it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
        )["NetworkInterfaces"]
        if not enis:
            break
        time.sleep(2)
    _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet_id))


def _retry_delete(fn, timeout_s: float = 600, delay: float = 2.0) -> None:
    """Run a teardown delete, retrying only dependency-not-yet-released codes until the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - retry only known dependency-not-yet-released codes
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code not in _RETRY_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(delay)


def _delete_instance(rds, inst_id: str, timeout_s: float = 1800) -> None:
    """Teardown: delete the instance and wait until it is gone so its network can be removed."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
    except Exception as exc:  # noqa: BLE001 - tolerate an instance already deleting or gone
        if getattr(exc, "response", {}).get("Error", {}).get("Code", "") not in (
            "DBInstanceNotFound", "InvalidDBInstanceState",
        ):
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=inst_id)
        except Exception as exc:  # noqa: BLE001 - not-found ends the wait
            if getattr(exc, "response", {}).get("Error", {}).get("Code") == "DBInstanceNotFound":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"DB instance {inst_id} still visible {timeout_s}s after delete")


def _deploy_cfn(ctx, template_body, parameters=None, timeout_s=1800) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rds-cfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters or [],
        # ROLLBACK (not DELETE) so a failed create leaves the stack and its events behind for
        # _cleanup (and the diagnostic read below) instead of vanishing before either can run.
        OnFailure="ROLLBACK",
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(_cleanup)
    max_attempts = max(int(timeout_s // 2), 1)
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts}
        )
    except Exception as exc:
        try:
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            reasons = [
                f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
                for e in events
                if e.get("ResourceStatus", "").endswith("FAILED")
            ]
        except Exception:
            # OnFailure=DELETE can remove the stack (and its events) before we get here.
            reasons = [f"<stack already gone: {exc}>"]
        raise _StackCreateFailed(f"stack {stack_name} failed to create: {reasons}") from exc
    return stack_name


def _stack_outputs(ctx, stack_name) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
