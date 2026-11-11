"""eks-enable-cluster-logging-creates-log-group."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eks-enable-cluster-logging-creates-log-group"
GROUP = "control-plane-logging"
SERVICES = ["ecr", "eks", "logs"]

_EKS_CLUSTER_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Enabling the 'api' control-plane log type creates /aws/eks/<cluster>/cluster
    with delivered log streams in CloudWatch Logs."""
    net = _create_vpc_and_subnets(ctx)
    role_arn = _create_eks_role(ctx)["role_arn"]
    name = ctx.unique_name("sim2real-eks-")
    _create_eks_cluster(
        ctx,
        name,
        role_arn,
        net["subnet_ids"],
        cluster_logging=[{"types": ["api"], "enabled": True}],
    )
    log_group_name = f"/aws/eks/{name}/cluster"
    _register_cluster_cleanup(ctx, name, log_group_name)

    _wait_cluster_active(ctx, name)

    present = _poll_log_group_present(ctx, log_group_name, timeout_s=360.0)
    assert present, f"log group {log_group_name} never appeared after enabling api logging"

    streams = _poll_log_streams(ctx, log_group_name, timeout_s=300.0)
    assert len(streams) >= 1, f"no log streams delivered into {log_group_name}"


# ===== helpers =====

def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_and_subnets(ctx) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-eks-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]

    def _cleanup_vpc() -> None:
        _safe_delete(lambda: ec2.delete_vpc(VpcId=vpc_id))

    ctx.on_cleanup(_cleanup_vpc)
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-subnet-{i}")],
        )["Subnet"]["SubnetId"]

        def _cleanup_subnet(sid: str = subnet_id) -> None:
            _safe_delete(lambda: ec2.delete_subnet(SubnetId=sid))

        ctx.on_cleanup(_cleanup_subnet)
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _safe_delete(fn, attempts: int = 6, delay_s: float = 15.0) -> None:
    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("DependencyViolation", "InvalidParameterValue") and attempt < attempts - 1:
                time.sleep(delay_s)
                continue
            return
        except Exception:
            return


def _create_eks_role(ctx, deny_logs: bool = False) -> dict[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn=_EKS_CLUSTER_POLICY_ARN)
    if deny_logs:
        deny_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "*",
                    }
                ],
            }
        )
        iam.put_role_policy(RoleName=name, PolicyName="deny-logs-delivery", PolicyDocument=deny_policy)

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="deny-logs-delivery")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=_EKS_CLUSTER_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return {"role_arn": role_arn, "role_name": name}


def _create_eks_cluster(ctx, name, role_arn, subnet_ids, cluster_logging=None) -> None:
    eks = ctx.client("eks")
    kwargs: dict[str, Any] = {"name": name, "roleArn": role_arn, "resourcesVpcConfig": {"subnetIds": subnet_ids}}
    if cluster_logging is not None:
        kwargs["logging"] = {"clusterLogging": cluster_logging}
    deadline = time.monotonic() + 120.0
    while True:
        try:
            eks.create_cluster(**kwargs)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "InvalidParameterException" and time.monotonic() < deadline:
                # IAM role trust may not have propagated to EKS yet; retry until it does.
                time.sleep(2)
                continue
            raise


def _register_cluster_cleanup(ctx, name, log_group_name) -> None:
    eks = ctx.client("eks")
    logs = ctx.client("logs")

    def _cleanup() -> None:
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 600.0
        gone = False
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as err:
                if err.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                gone = True
                break
            time.sleep(2)
        try:
            logs.delete_log_group(logGroupName=log_group_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        if not gone:
            raise AssertionError(f"cluster {name} still present 600s after DeleteCluster")

    ctx.on_cleanup(_cleanup)


def _wait_cluster_active(ctx, name, timeout_s: float = 1200.0) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not become ACTIVE within {timeout_s}s")


def _poll_log_group_present(ctx, log_group_name, timeout_s: float = 360.0, interval_s: float = 20.0) -> bool:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        if any(g["logGroupName"] == log_group_name for g in resp.get("logGroups", [])):
            return True
        time.sleep(interval_s)
    return False


def _poll_log_streams(ctx, log_group_name, timeout_s: float = 300.0, interval_s: float = 20.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        streams = logs.describe_log_streams(logGroupName=log_group_name).get("logStreams", [])
        if streams:
            return streams
        time.sleep(interval_s)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
