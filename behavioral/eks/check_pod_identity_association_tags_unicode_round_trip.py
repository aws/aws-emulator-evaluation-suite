"""pod-identity-association-tags-unicode-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "pod-identity-association-tags-unicode-round-trip"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tags on a pod identity association, set at create and by TagResource, read back exact: the
    create response, DescribePodIdentityAssociation and ListTagsForResource agree byte for byte."""
    eks = ctx.client("eks")
    cluster = _create_cluster(ctx)
    pod_role_arn = _create_pod_identity_role(ctx)

    # Pod identity association tags reject symbol codepoints (emoji, checkmarks), so only
    # non-ASCII letters are used, isolating the round-trip from that character-class validation.
    initial_tags = {
        "键-unicode": "日本語-テスト",
        "ключ-key": "value-with-áccents-ñ-ü",
    }
    assoc = eks.create_pod_identity_association(
        clusterName=cluster["name"],
        namespace="default",
        serviceAccount=ctx.unique_name("sim2real-eks-sa-")[:63].lower(),
        roleArn=pod_role_arn,
        tags=initial_tags,
    )["association"]
    association_id = assoc["associationId"]
    association_arn = assoc["associationArn"]
    ctx.on_cleanup(
        lambda: eks.delete_pod_identity_association(
            clusterName=cluster["name"], associationId=association_id
        )
    )

    # The create response itself must already carry the exact Unicode tags back.
    assert assoc["tags"] == initial_tags, (
        f"expected create response tags {initial_tags!r}, got {assoc.get('tags')!r}"
    )

    extra_tags = {"追加タグ": "second-round-trip-done"}
    eks.tag_resource(resourceArn=association_arn, tags=extra_tags)

    described = eks.describe_pod_identity_association(
        clusterName=cluster["name"], associationId=association_id
    )["association"]
    expected_tags = {**initial_tags, **extra_tags}
    assert described["tags"] == expected_tags, (
        f"expected merged tags {expected_tags!r} from DescribePodIdentityAssociation, "
        f"got {described.get('tags')!r}"
    )

    listed = eks.list_tags_for_resource(resourceArn=association_arn)["tags"]
    assert listed == expected_tags, (
        f"expected merged tags {expected_tags!r} from ListTagsForResource, got {listed!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _create_vpc_stack(ctx):
    """Prefer the run's shared network (spares the per-region VPC quota); else create a VPC."""
    ec2 = ctx.client("ec2")

    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())[:3]
        if len(subnet_ids) >= 2:
            sg_id = ec2.create_security_group(
                VpcId=vpc_id,
                GroupName=ctx.unique_name("sim2real-eks-sg-"),
                Description="sim2real eks behavioral check security group",
            )["GroupId"]
            ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
            return {"subnet_ids": subnet_ids, "security_group_ids": [sg_id]}

    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-subnet-{i}-")}]}
            ],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-eks-sg-"),
        Description="sim2real eks behavioral check security group",
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    return {"subnet_ids": subnet_ids, "security_group_ids": [sg_id]}


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_pod_identity_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-podrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_cluster(ctx):
    eks = ctx.client("eks")
    vpc_cfg = _create_vpc_stack(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")

    deadline = time.monotonic() + 90.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": vpc_cfg["subnet_ids"],
                    "securityGroupIds": vpc_cfg["security_group_ids"],
                },
            )
            break
        except eks.exceptions.ClientException as exc:
            last_error = exc
            time.sleep(2)
    else:
        raise AssertionError(f"CreateCluster never succeeded (IAM propagation?): {last_error}")

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))

    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert cluster["status"] == "ACTIVE", f"cluster reached status {cluster['status']}"
    return cluster


# A cluster, load balancer, endpoint or instance in this VPC deletes asynchronously: its ENIs linger
# in the subnet / security group, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails
# with DependencyViolation. Wait (bounded) for the ENIs to go, retry DependencyViolation in the same
# window, then raise naming the ENIs still attached. One window is shared by a check's network deletes.
_NET_TEARDOWN_S = 1260.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
