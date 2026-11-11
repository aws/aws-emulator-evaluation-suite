"""nodegroup-labels-taints-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "nodegroup-labels-taints-round-trip"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Nodegroup label maps and taint lists survive CreateNodegroup and UpdateNodegroupConfig unchanged."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    cluster_name = cluster["name"]
    subnets = cluster["resourcesVpcConfig"]["subnetIds"]

    node_role_arn = _create_node_role(ctx)
    nodegroup_name = ctx.unique_name("sim2real-ng-")

    labels = {"team": "platform-eng", "tier.example.com/role": "worker", "removable-label": "temp"}
    taints = [
        {"key": "dedicated", "value": "gpu-workload", "effect": "NO_SCHEDULE"},
        {"key": "special.io/spot", "value": "true", "effect": "PREFER_NO_SCHEDULE"},
    ]

    _create_nodegroup_retrying_role_propagation(
        eks,
        dict(
            clusterName=cluster_name,
            nodegroupName=nodegroup_name,
            subnets=subnets,
            nodeRole=node_role_arn,
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            labels=labels,
            taints=taints,
            tags={"sim2real": "1"},
        ),
    )
    ctx.on_cleanup(lambda: _delete_nodegroup_safe(ctx, cluster_name, nodegroup_name))
    _wait_for_nodegroup_active(ctx, cluster_name, nodegroup_name)

    described = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
    assert described["labels"] == labels, f"labels mutated on create: {described['labels']!r} != {labels!r}"
    assert described["taints"] == taints, f"taints mutated on create: {described['taints']!r} != {taints!r}"

    update = eks.update_nodegroup_config(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        labels={"addOrUpdateLabels": {"new-label": "added-value"}, "removeLabels": ["removable-label"]},
        taints={
            "addOrUpdateTaints": [{"key": "extra", "value": "x", "effect": "NO_EXECUTE"}],
            "removeTaints": [{"key": "special.io/spot", "value": "true", "effect": "PREFER_NO_SCHEDULE"}],
        },
    )["update"]
    _wait_for_nodegroup_update(ctx, cluster_name, nodegroup_name, update["id"])

    described_after = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
    expected_labels = {"team": "platform-eng", "tier.example.com/role": "worker", "new-label": "added-value"}
    assert described_after["labels"] == expected_labels, (
        f"post-update labels mismatch: {described_after['labels']!r} != {expected_labels!r}"
    )

    expected_taints = {
        ("dedicated", "gpu-workload", "NO_SCHEDULE"),
        ("extra", "x", "NO_EXECUTE"),
    }
    actual_taints = {(t["key"], t["value"], t["effect"]) for t in described_after["taints"]}
    assert actual_taints == expected_taints, (
        f"post-update taints mismatch: {actual_taints!r} != {expected_taints!r}"
    )


def _create_nodegroup_retrying_role_propagation(eks, kwargs, timeout_s=120.0, interval_s=10.0):
    """IAM role trust is eventually consistent; EKS rejects a brand-new nodeRole with
    ClientException until it has propagated, so retry CreateNodegroup itself rather than
    guessing a fixed delay."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            eks.create_nodegroup(**kwargs)
            return
        except eks.exceptions.ClientException as exc:
            last_error = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateNodegroup never succeeded (IAM role propagation?): {last_error}")

def _get_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision the EKS cluster prerequisite subnets")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in >=2 availability zones for an EKS cluster")
    return list(by_az.values())[:3]


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for _ in range(10):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role["Arn"]


def _create_node_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-node-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]
    policy_arns = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup():
        for arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for _ in range(10):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role["Arn"]


def _wait_for_cluster_active(ctx, name, timeout_s=1200.0, interval_s=20.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        status = cluster["status"]
        if status == "ACTIVE":
            return cluster
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within {timeout_s}s")


def _delete_cluster_safe(ctx, name):
    eks = ctx.client("eks")
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            status = eks.describe_cluster(name=name)["cluster"]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status not in ("CREATING", "UPDATING", "DELETING"):
            break
        time.sleep(15)
    _delete_eks_cluster_retrying(eks, name)


def _create_active_cluster(ctx, **extra_kwargs):
    eks = ctx.client("eks")
    subnets = _get_two_az_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnets},
        tags={"sim2real": "1"},
    )
    kwargs.update(extra_kwargs)
    _create_cluster_retrying_role_propagation(eks, kwargs)
    ctx.on_cleanup(lambda: _delete_cluster_safe(ctx, name))
    return _wait_for_cluster_active(ctx, name)


def _create_cluster_retrying_role_propagation(eks, kwargs, timeout_s=120.0, interval_s=10.0):
    """IAM role trust is eventually consistent; EKS rejects a brand-new roleArn with
    ClientException until it has propagated, so retry CreateCluster itself rather than
    guessing a fixed delay."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            return
        except eks.exceptions.ClientException as exc:
            last_error = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateCluster never succeeded (IAM role propagation?): {last_error}")


def _wait_for_nodegroup_active(ctx, cluster_name, nodegroup_name, timeout_s=1500.0, interval_s=20.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        nodegroup = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
        status = nodegroup["status"]
        if status == "ACTIVE":
            return nodegroup
        if status == "CREATE_FAILED":
            raise AssertionError(f"nodegroup {nodegroup_name} entered CREATE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} did not reach ACTIVE within {timeout_s}s")


def _delete_nodegroup_safe(ctx, cluster_name, nodegroup_name, timeout_s=900.0, interval_s=20.0):
    eks = ctx.client("eks")
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(interval_s)


def _wait_for_nodegroup_update(ctx, cluster_name, nodegroup_name, update_id, timeout_s=600.0, interval_s=15.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        update = eks.describe_update(name=cluster_name, nodegroupName=nodegroup_name, updateId=update_id)["update"]
        status = update["status"]
        if status != "InProgress":
            if status != "Successful":
                raise AssertionError(f"update {update_id} ended in {status}: {update.get('errors')}")
            return update
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} did not complete within {timeout_s}s")



def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
