"""delete-cluster-with-active-nodegroup-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-with-active-nodegroup-rejected"
GROUP = "e2e"
SERVICES = ["eks"]

_TAGS = {"sim2real:managed": "true"}
_IAM_TAGS = [{"Key": k, "Value": v} for k, v in _TAGS.items()]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on a cluster that still has an attached nodegroup is rejected with
    ResourceInUseException, the cluster is left untouched (still ACTIVE and describable),
    and once the nodegroup is removed the same DeleteCluster call succeeds (positive control)."""
    vpc = _create_vpc_infra(ctx)
    cluster_role_arn = _create_cluster_role(ctx)
    node_role_arn = _create_node_role(ctx)

    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-delrej-")
    _create_cluster_via_sdk(ctx, cluster_name, cluster_role_arn, vpc["subnet_ids"])

    nodegroup_name = ctx.unique_name("sim2real-eks-delrej-ng-")
    eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        subnets=vpc["subnet_ids"],
        nodeRole=node_role_arn,
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
        instanceTypes=["t3.medium"],
        amiType="AL2023_x86_64_STANDARD",
        tags=dict(_TAGS),
    )
    ctx.on_cleanup(lambda: _delete_nodegroup_and_wait(ctx, cluster_name, nodegroup_name))
    _wait_nodegroup_status(ctx, cluster_name, nodegroup_name, "ACTIVE", timeout_s=900)

    code, message = _error(lambda: eks.delete_cluster(name=cluster_name))
    assert code == "ResourceInUseException", (
        f"DeleteCluster with an ACTIVE dependent nodegroup should be refused with "
        f"ResourceInUseException, got {code!r}"
    )
    assert message == "Cluster has nodegroups attached", message

    # Effect absent: the cluster was NOT deleted or put into a deleting state.
    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
    assert cluster["status"] == "ACTIVE", (
        f"a refused DeleteCluster must not mutate the cluster; status is {cluster['status']!r}"
    )

    # Positive control: after removing the blocking nodegroup, deletion succeeds for real.
    eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    _wait_nodegroup_deleted(ctx, cluster_name, nodegroup_name, timeout_s=600)

    eks.delete_cluster(name=cluster_name)
    _wait_cluster_deleted(ctx, cluster_name, timeout_s=600)

    not_found_message = f"No cluster found for name: {cluster_name}."
    final_code, final_message = _error(lambda: eks.describe_cluster(name=cluster_name))
    assert final_code == "ResourceNotFoundException", (
        f"DescribeCluster on the deleted cluster should be ResourceNotFoundException, "
        f"got {final_code!r}"
    )
    assert final_message == not_found_message, final_message

    # Gone means gone: a mutation on the dead id also fails, the same way.
    dead_code, dead_message = _error(lambda: eks.delete_cluster(name=cluster_name))
    assert dead_code == "ResourceNotFoundException", (
        f"DeleteCluster on the already-deleted cluster should also be "
        f"ResourceNotFoundException, got {dead_code!r}"
    )
    assert dead_message == not_found_message, dead_message


# ===== helpers =====
def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _create_vpc_infra(ctx) -> dict:
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        subnet_ids = sorted({s["SubnetId"] for s in subnets})[:3]
        if len(subnet_ids) >= 2:
            return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": None}

    # No usable shared network (a freshly provisioned account may not have one) -- provision a
    # dedicated one instead of failing on an environment assumption.
    return _create_dedicated_vpc_infra(ctx)


def _create_dedicated_vpc_infra(ctx) -> dict:
    ec2 = ctx.client("ec2")
    tag_spec = lambda resource_type, name: [  # noqa: E731
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, *_IAM_TAGS],
        }
    ]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.83.0.0/16",
        TagSpecifications=tag_spec("vpc", ctx.unique_name("sim2real-eks-delrej-vpc-")),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=tag_spec("internet-gateway", ctx.unique_name("sim2real-eks-delrej-igw-"))
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _teardown_igw():
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        _retry_delete(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))

    ctx.on_cleanup(_teardown_igw)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=tag_spec("route-table", ctx.unique_name("sim2real-eks-delrej-rt-"))
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region} does not have >=2 available AZs for EKS subnets")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.83.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=tag_spec("subnet", ctx.unique_name(f"sim2real-eks-delrej-subnet{i}-")),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=aid)))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": None}


def _retry_delete(fn) -> None:
    """Run a network teardown call: deletes go through _delete_net, which retries DependencyViolation;
    the route-table disassociation is called directly. A ...NotFound code counts as deleted; other errors raise."""
    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response["Error"]["Code"]:
            raise



def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-cluster-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=list(_IAM_TAGS)
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _create_node_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-node-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=list(_IAM_TAGS)
    )["Role"]["Arn"]
    policies = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    ]

    def _cleanup():
        try:
            for p in policies:
                try:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    for p in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=p)
    return role_arn


def _create_cluster_via_sdk(ctx, name: str, role_arn: str, subnet_ids: list[str]) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags=dict(_TAGS),
            )
            break
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))
    _wait_cluster_status(ctx, name, "ACTIVE", timeout_s=1200)


def _wait_cluster_status(ctx, name: str, target: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        last_status = cluster["status"]
        if last_status == target:
            return cluster
        if last_status in ("FAILED",):
            raise AssertionError(f"cluster {name} entered terminal status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s (last={last_status})")


def _delete_cluster_and_wait(ctx, name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    try:
        _delete_eks_cluster_retrying(eks, name)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        raise
    _wait_cluster_deleted(ctx, name, timeout_s=timeout_s, interval_s=interval_s)


def _wait_cluster_deleted(ctx, name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _wait_nodegroup_status(ctx, cluster_name: str, nodegroup_name: str, target: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> dict:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
        last_status = ng["status"]
        if last_status == target:
            return ng
        if last_status in ("CREATE_FAILED", "DELETE_FAILED"):
            raise AssertionError(f"nodegroup {nodegroup_name} entered terminal status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} did not reach {target} within {timeout_s}s (last={last_status})")


def _delete_nodegroup_and_wait(ctx, cluster_name: str, nodegroup_name: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        raise
    _wait_nodegroup_deleted(ctx, cluster_name, nodegroup_name, timeout_s=timeout_s, interval_s=interval_s)


def _wait_nodegroup_deleted(ctx, cluster_name: str, nodegroup_name: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} was not deleted within {timeout_s}s")


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
        _time.sleep(2)
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
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]



def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
