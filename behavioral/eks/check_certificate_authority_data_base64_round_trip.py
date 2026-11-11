"""certificate-authority-data-base64-round-trip."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags


CHECK = "certificate-authority-data-base64-round-trip"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The EKS-generated base64 `data` of a new certificate authority is byte-identical across repeated
    DescribeCertificateAuthority calls and decodes and re-encodes to itself (canonical encoding)."""
    eks = ctx.client("eks")
    cluster = _create_cluster(ctx)

    created = eks.create_certificate_authority(clusterName=cluster["name"])["certificateAuthority"]
    ca_id = created["id"]
    ctx.on_cleanup(
        lambda: _delete_certificate_authority_when_idle(eks, cluster["name"], ca_id)
    )

    described = _poll_until(
        lambda: eks.describe_certificate_authority(clusterName=cluster["name"], certificateAuthorityId=ca_id)[
            "certificateAuthority"
        ],
        lambda ca: bool(ca.get("data")),
        timeout_s=600.0,
        interval_s=15.0,
    )
    data1 = described["data"]

    described_again = eks.describe_certificate_authority(
        clusterName=cluster["name"], certificateAuthorityId=ca_id
    )["certificateAuthority"]
    data2 = described_again["data"]

    assert data1 == data2, "certificate authority data changed between two describes"

    described_later = eks.describe_certificate_authority(
        clusterName=cluster["name"], certificateAuthorityId=ca_id
    )["certificateAuthority"]
    data3 = described_later["data"]

    assert data3 == data1, "certificate authority data changed on a third describe"

    decoded = base64.b64decode(data1)
    assert base64.b64encode(decoded).decode("ascii") == data1, "base64 data is not canonically encoded"
    assert len(decoded) > 0, "decoded certificate authority data is empty"


# ===== helpers =====


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
    """Prefer the account's default VPC (avoids the 5-VPC-per-region default quota
    being exhausted by repeated check runs); only create a dedicated VPC as a fallback."""
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

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]][:2]
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


# EC2 network teardown: a cluster in this VPC deletes asynchronously and its ENIs keep DeleteSubnet /
# DeleteVpc failing with DependencyViolation for minutes, so wait for the ENIs, retry that code to one
# deadline shared by the check's network deletes, then raise naming the ENIs still attached.
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


def _delete_certificate_authority_when_idle(eks, cluster_name, ca_id, timeout_s=900.0, interval_s=20.0):
    """DeleteCertificateAuthority, retried while an earlier CA update on the cluster still runs."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the network.

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
