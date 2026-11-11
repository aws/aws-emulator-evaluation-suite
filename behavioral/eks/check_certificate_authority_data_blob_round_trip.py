"""certificate-authority-data-blob-round-trip."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "certificate-authority-data-blob-round-trip"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCluster's certificateAuthority.data, generated once at CreateCluster, is well-formed
    base64 and byte-identical across independent reads, not re-derived or re-encoded per read."""
    eks = ctx.client("eks")
    prereqs = _setup_network_and_role(ctx)
    name = ctx.unique_name("sim2real-eks-ca-")
    _create_active_cluster(ctx, eks, name, prereqs["role_arn"], prereqs["subnet_ids"])

    data_1 = _wait_for_ca_data(ctx, eks, name)
    base64.b64decode(data_1, validate=True)  # must be well-formed base64

    for read_no in (2, 3):
        time.sleep(5)
        data_n = eks.describe_cluster(name=name)["cluster"]["certificateAuthority"]["data"]
        assert data_n == data_1, (
            f"certificateAuthority.data changed on read {read_no}: first={data_1!r} later={data_n!r}"
        )


# ===== helpers =====
def _wait_for_ca_data(ctx, eks, cluster_name, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=cluster_name)["cluster"]
        data = cluster.get("certificateAuthority", {}).get("data")
        if data:
            return data
        time.sleep(5)
    raise AssertionError(f"cluster {cluster_name} never populated certificateAuthority.data within {timeout_s}s")


def _get_or_create_subnets(ctx, ec2):
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())[:2]
        if len(subnet_ids) >= 2:
            return vpc_id, subnet_ids
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-subnet-")}])
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _setup_network_and_role(ctx):
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    vpc_id, subnet_ids = _get_or_create_subnets(ctx, ec2)
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "role_arn": role_arn, "role_name": role_name}


def _create_active_cluster(ctx, eks, name, role_arn, subnet_ids, timeout_s=1500, **extra):
    deadline = time.monotonic() + 90
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = eks.create_cluster(
                name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}, **extra
            )
            break
        except Exception as exc:  # fresh IAM role can take a few seconds to propagate
            last_exc = exc
            time.sleep(5)
    if resp is None:
        raise last_exc

    def _cleanup_cluster():
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_cluster)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=name)["cluster"]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within {timeout_s}s")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
