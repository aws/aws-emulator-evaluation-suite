"""eks-cluster-log-group-naming-follows-convention-per-cluster."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eks-cluster-log-group-naming-follows-convention-per-cluster"
GROUP = "workload-logging"
SERVICES = ["ecr", "eks", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two independent EKS clusters, each with control-plane 'api' logging enabled, each
    get their OWN distinctly-named CloudWatch Logs group (/aws/eks/<cluster>/cluster) with
    their own log streams, and neither cluster's log content leaks into the other's group."""
    net = _create_vpc_and_subnets(ctx)
    role_arn = _create_eks_role(ctx)["role_arn"]

    name1 = ctx.unique_name("sim2real-eksiso-a-")
    name2 = ctx.unique_name("sim2real-eksiso-b-")
    log_group1 = f"/aws/eks/{name1}/cluster"
    log_group2 = f"/aws/eks/{name2}/cluster"

    ctx.client("eks")
    for name, group in ((name1, log_group1), (name2, log_group2)):
        _create_eks_cluster(ctx, name, role_arn, net["subnet_ids"], cluster_logging=[{"types": ["api"], "enabled": True}])
        _register_cluster_cleanup(ctx, name, group)

    _wait_clusters_active(ctx, [name1, name2])

    present1 = _poll_log_group_present(ctx, log_group1, timeout_s=360.0)
    present2 = _poll_log_group_present(ctx, log_group2, timeout_s=360.0)
    assert present1, f"log group {log_group1} never appeared for cluster {name1}"
    assert present2, f"log group {log_group2} never appeared for cluster {name2}"
    assert log_group1 != log_group2, "both clusters produced the SAME log group name"

    streams1 = _poll_log_streams(ctx, log_group1, timeout_s=300.0)
    streams2 = _poll_log_streams(ctx, log_group2, timeout_s=300.0)
    assert streams1, f"no log streams delivered into {log_group1}"
    assert streams2, f"no log streams delivered into {log_group2}"

    # Isolation: cluster 2's own name must never appear inside cluster 1's log content
    # (and vice versa) -- an emulator that shares one backing store across clusters would
    # leak content across the two independently-named groups.
    logs = ctx.client("logs")
    hits_of_2_in_1 = logs.filter_log_events(logGroupName=log_group1, filterPattern=f'"{name2}"').get("events", [])
    hits_of_1_in_2 = logs.filter_log_events(logGroupName=log_group2, filterPattern=f'"{name1}"').get("events", [])
    assert hits_of_2_in_1 == [], f"cluster {name2}'s name appeared inside cluster {name1}'s log group {log_group1}"
    assert hits_of_1_in_2 == [], f"cluster {name1}'s name appeared inside cluster {name2}'s log group {log_group2}"

    # No identical event content shared between the two groups either.
    msgs1 = {e["message"] for e in logs.filter_log_events(logGroupName=log_group1, limit=50).get("events", [])}
    msgs2 = {e["message"] for e in logs.filter_log_events(logGroupName=log_group2, limit=50).get("events", [])}
    overlap = msgs1 & msgs2
    assert overlap == set(), f"identical log events shared between {log_group1} and {log_group2}: {list(overlap)[:2]}"


# ===== helpers =====

_EKS_CLUSTER_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_and_subnets(ctx) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-eksiso-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.63.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]

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
            CidrBlock=f"10.63.{i}.0/24",
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


def _create_eks_role(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eksiso-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "Name", "Value": name}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn=_EKS_CLUSTER_POLICY_ARN)

    def _cleanup() -> None:
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
    kwargs: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "resourcesVpcConfig": {"subnetIds": subnet_ids},
        "tags": {"Name": name},
    }
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
                time.sleep(2)
                continue
            raise


def _register_cluster_cleanup(ctx, name, log_group_name) -> None:
    eks = ctx.client("eks")
    logs = ctx.client("logs")

    # Issue both deletes and return: EKS finishes a control-plane deletion asynchronously, and
    # waiting for it here would spend the shared cleanup budget that the other cluster's delete,
    # the IAM role and the VPC teardown registered after this one need.
    def _cleanup() -> None:
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            logs.delete_log_group(logGroupName=log_group_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)


def _wait_clusters_active(ctx, names, timeout_s: float = 1500.0) -> None:
    eks = ctx.client("eks")
    pending = set(names)
    deadline = time.monotonic() + timeout_s
    while pending and time.monotonic() < deadline:
        for name in list(pending):
            status = eks.describe_cluster(name=name)["cluster"]["status"]
            if status == "ACTIVE":
                pending.discard(name)
            elif status == "FAILED":
                raise AssertionError(f"cluster {name} entered FAILED status")
        if pending:
            time.sleep(2)
    if pending:
        raise AssertionError(f"clusters {pending} did not become ACTIVE within {timeout_s}s")


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
