"""target-group-registration-denied-without-elasticloadbalancing-permission."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-group-registration-denied-without-elasticloadbalancing-permission"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_SESSION_NAME = "sim2real-behav-noperm"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """RegisterTargets called with credentials for an IAM role that has zero attached
    policies is denied with AccessDenied and writes no target state, while the
    identical call made with the harness's normal (permissioned) credentials succeeds.
    """
    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    sg_id = _default_sg(ctx, vpc_id)
    instance_id = _launch_instance(ctx, subnet_ids[0], sg_id, ctx.unique_name("sim2real-noperm-inst-"))
    tg_arn = _create_target_group(ctx, vpc_id, ctx.unique_name("sim2real-noperm-tg-"))

    role_arn = _create_zero_permission_role(ctx, ctx.unique_name("sim2real-noperm-role-"))
    creds = _assume_role_with_retry(ctx, role_arn, timeout_s=60.0, interval_s=5.0)
    restricted_elbv2 = _client_with_credentials(ctx, "elbv2", creds)

    code, message = _error(
        lambda: restricted_elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": instance_id, "Port": 80}])
    )
    # elbv2 uses the Query protocol: real AWS returns the error code "AccessDenied" (not the
    # "AccessDeniedException" shape used by JSON-protocol services) for an implicit IAM deny.
    assert code == "AccessDenied", f"expected an access-denied error, got {code}"
    account_id = role_arn.split(":")[4]
    role_name = role_arn.rsplit("/", 1)[1]
    action = "elasticloadbalancing:RegisterTargets"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: {action} on resource: {tg_arn} because no identity-based "
        f"policy allows the {action} action"
    )
    assert message == expected_message, f"AccessDenied message {message!r}, expected {expected_message!r}"

    elbv2 = ctx.client("elbv2")
    registered = elbv2.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", [])
    assert registered == [], f"target group should have no registered targets, found {registered}"

    # Positive control: the identical call with the harness's normally-permissioned
    # credentials succeeds against the same target group and instance.
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": instance_id, "Port": 80}])
    registered = elbv2.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", [])
    registered_ids = {d["Target"]["Id"] for d in registered}
    assert instance_id in registered_ids, "control registration with full permissions did not take effect"


def _tag_spec(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _default_vpc_subnets(ctx: Any, min_count: int = 2) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host the test ALB/EC2 topology")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < min_count:
        raise AssertionError(f"shared network has fewer than {min_count} distinct-AZ subnets")
    return vpc_id, subnet_ids[:min_count]


def _default_sg(ctx: Any, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group to launch the test instance into")
    return sgs[0]["GroupId"]


def _latest_al2023_ami(ctx: Any) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _terminate_and_wait(ctx: Any, instance_id: str) -> None:
    ec2 = ctx.client("ec2")
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _launch_instance(ctx: Any, subnet_id: str, sg_id: str, name: str) -> str:
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    instance_id = ec2.run_instances(
        ImageId=ami_id, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id]}],
        TagSpecifications=_tag_spec("instance", name),
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id


def _create_target_group(
    ctx: Any, vpc_id: str, name: str, protocol: str = "HTTP", port: int = 80, health_path: str = "/",
) -> str:
    elbv2 = ctx.client("elbv2")
    tg_arn = elbv2.create_target_group(
        Name=name, Protocol=protocol, Port=port, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol=protocol, HealthCheckPath=health_path,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    return tg_arn


def _create_zero_permission_role(ctx: Any, role_name: str) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real behavioral test role with zero attached permissions",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _assume_role_with_retry(ctx: Any, role_arn: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> dict:
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)
            return resp["Credentials"]
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_err}")


def _client_with_credentials(ctx: Any, service: str, creds: dict) -> Any:
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _error(fn: Any) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be denied, but it succeeded and returned {result!r}")



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
