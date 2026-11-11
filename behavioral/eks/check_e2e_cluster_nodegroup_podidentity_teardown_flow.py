"""e2e-cluster-nodegroup-podidentity-teardown-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-cluster-nodegroup-podidentity-teardown-flow"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCluster is refused while a nodegroup is attached and the cluster stays ACTIVE; deleting the
    nodegroup and then the cluster leaves the pod identity association, the nodegroup and the cluster
    all ResourceNotFoundException on Describe*."""
    # Per-run state: the teardown deadlines, started by the first teardown that asks for each.
    run_state: dict = {}
    eks = ctx.client("eks")

    subnet_ids = _create_network(ctx, run_state)
    cluster_role_arn = _create_role(
        ctx,
        "cluster",
        "eks.amazonaws.com",
        ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
    )
    node_role_arn = _create_role(
        ctx,
        "node",
        "ec2.amazonaws.com",
        [
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        ],
    )
    pod_role_arn = _create_pod_identity_role(ctx)

    cluster_name = ctx.unique_name("sim2real-eks-cl-")
    _create_cluster_with_retry(ctx, cluster_name, cluster_role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _delete_cluster(eks, run_state, cluster_name))
    _wait_cluster_status(ctx, cluster_name, {"ACTIVE"}, timeout_s=1200)

    nodegroup_name = ctx.unique_name("sim2real-eks-ng-")
    eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        subnets=subnet_ids,
        nodeRole=node_role_arn,
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
        instanceTypes=["t3.small"],
    )
    ctx.on_cleanup(lambda: _delete_nodegroup(eks, run_state, cluster_name, nodegroup_name))
    _wait_nodegroup_status(ctx, cluster_name, nodegroup_name, {"ACTIVE"}, timeout_s=900)

    association = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace="default",
        serviceAccount=ctx.unique_name("sa-"),
        roleArn=pod_role_arn,
    )["association"]
    assoc_id = association["associationId"]

    described = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=assoc_id
    )["association"]
    assert described["roleArn"] == pod_role_arn, (
        f"expected pod identity association roleArn {pod_role_arn!r}, got {described['roleArn']!r}"
    )
    assert described["namespace"] == "default", (
        f"expected pod identity association namespace 'default', got {described['namespace']!r}"
    )

    # Negative: a cluster with an attached nodegroup cannot be deleted.
    code, message = _error_code(lambda: eks.delete_cluster(name=cluster_name))
    assert code == "ResourceInUseException", (
        f"expected DeleteCluster with an attached nodegroup to fail with "
        f"ResourceInUseException, got {code!r}"
    )
    assert message == "Cluster has nodegroups attached", message
    status = eks.describe_cluster(name=cluster_name)["cluster"]["status"]
    assert status == "ACTIVE", f"expected cluster to remain ACTIVE after the rejected delete, got {status!r}"

    eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    _wait_nodegroup_deleted(ctx, cluster_name, nodegroup_name, timeout_s=900)

    # Positive control: with the nodegroup gone, cluster deletion succeeds once the cluster's
    # in-flight update settles (DeleteCluster refuses that with ResourceInUseException).
    _delete_cluster_when_settled(ctx, eks, cluster_name)
    _wait_cluster_deleted(ctx, cluster_name, timeout_s=900)

    pod_identity_read_code, pod_identity_read_message = _error_code(
        lambda: eks.describe_pod_identity_association(
            clusterName=cluster_name, associationId=assoc_id
        )
    )
    assert pod_identity_read_code == "ResourceNotFoundException", (
        f"expected describe_pod_identity_association after teardown to be "
        f"ResourceNotFoundException, got {pod_identity_read_code!r}"
    )
    assert pod_identity_read_message == f"No cluster found for name: {cluster_name}.", pod_identity_read_message
    nodegroup_read_code, _ = _error_code(
        lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    )
    assert nodegroup_read_code == "ResourceNotFoundException", (
        f"expected describe_nodegroup after teardown to be ResourceNotFoundException, got {nodegroup_read_code!r}"
    )
    cluster_read_code, cluster_read_message = _error_code(lambda: eks.describe_cluster(name=cluster_name))
    assert cluster_read_code == "ResourceNotFoundException", (
        f"expected describe_cluster after teardown to be ResourceNotFoundException, got {cluster_read_code!r}"
    )
    assert cluster_read_message == f"No cluster found for name: {cluster_name}.", cluster_read_message

    # A mutation on each dead id also fails, not just the read.
    pod_identity_delete_code, pod_identity_delete_message = _error_code(
        lambda: eks.delete_pod_identity_association(
            clusterName=cluster_name, associationId=assoc_id
        )
    )
    assert pod_identity_delete_code == "ResourceNotFoundException", (
        f"expected a delete_pod_identity_association on a torn-down cluster to be "
        f"ResourceNotFoundException, got {pod_identity_delete_code!r}"
    )
    assert pod_identity_delete_message == f"No cluster found for name: {cluster_name}.", pod_identity_delete_message
    nodegroup_delete_code, _ = _error_code(
        lambda: eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    )
    assert nodegroup_delete_code == "ResourceNotFoundException", (
        f"expected a second delete_nodegroup on a torn-down cluster to be "
        f"ResourceNotFoundException, got {nodegroup_delete_code!r}"
    )
    cluster_delete_code, cluster_delete_message = _error_code(lambda: eks.delete_cluster(name=cluster_name))
    assert cluster_delete_code == "ResourceNotFoundException", (
        f"expected a second delete_cluster on an already-deleted cluster to be "
        f"ResourceNotFoundException, got {cluster_delete_code!r}"
    )
    assert cluster_delete_message == f"No cluster found for name: {cluster_name}.", cluster_delete_message


def _absent_ok(fn, *gone_codes):
    """Run one teardown step; an error code in gone_codes means the resource is already gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in gone_codes:
            raise


def _delete_cluster_when_settled(ctx, eks, cluster_name, timeout_s=600.0):
    """DeleteCluster, retrying every 2 s only while it answers that an update is in progress."""
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))
    while True:
        try:
            eks.delete_cluster(name=cluster_name)
            return
        except ClientError as err:
            error = err.response["Error"]
            busy = error["Code"] == "ResourceInUseException" and "update" in error.get("Message", "")
            if not busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


#: One window per run, shared by the nodegroup and cluster teardowns and started by the first of
#: them; with the network teardown's _NET_TEARDOWN_S after it, the total stays within the suite's
#: 1,800 s cleanup budget.
_CLUSTER_TEARDOWN_S = 520.0


def _cluster_deadline(run_state: dict) -> float:
    """The run's one cluster-teardown deadline, started by the first teardown that asks for it."""
    return run_state.setdefault("cluster", time.monotonic() + _CLUSTER_TEARDOWN_S)


def _delete_nodegroup(eks, run_state: dict, cluster_name, nodegroup_name):
    """Delete the nodegroup unless it is gone and wait until it is; a nodegroup still creating
    refuses with ResourceInUseException, retried every 2 s."""
    from botocore.exceptions import ClientError

    deadline = _cluster_deadline(run_state)
    while True:
        try:
            eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise RuntimeError(f"nodegroup {nodegroup_name} still exists at the cluster-teardown deadline")


def _delete_cluster(eks, run_state: dict, cluster_name):
    """Delete the cluster and wait until it is gone. ResourceInUseException (nodegroups still
    attached, or an update in progress) is retried every 2 s; anything else raises."""
    from botocore.exceptions import ClientError

    deadline = _cluster_deadline(run_state)
    while True:
        try:
            eks.delete_cluster(name=cluster_name)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=cluster_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise RuntimeError(f"cluster {cluster_name} still exists at the cluster-teardown deadline")


def _error_code(fn):
    """(code, message) of the ClientError fn raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _create_network(ctx, run_state: dict):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _absent_ok(
        lambda: _delete_net(ec2, run_state, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[
            {"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-igw-")}]}
        ],
    )["InternetGateway"]["InternetGatewayId"]

    def _teardown_igw():
        _absent_ok(lambda: _delete_net(
            ec2, run_state, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id),
            "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound")
        _absent_ok(lambda: _delete_net(ec2, run_state, "delete_internet_gateway", InternetGatewayId=igw_id),
                   "InvalidInternetGatewayID.NotFound")

    ctx.on_cleanup(_teardown_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rt_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _absent_ok(lambda: _delete_net(ec2, run_state, "delete_route_table", RouteTableId=rt_id),
                                      "InvalidRouteTableID.NotFound"))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    azs = [
        a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"] if a["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-sn{i}-")}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _absent_ok(
            lambda: _delete_net(ec2, run_state, "delete_subnet", SubnetId=sid), "InvalidSubnetID.NotFound"))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_role(ctx, kind, trust_service, managed_policy_arns):
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-eks-{kind}-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
        }
    )
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    for policy_arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in managed_policy_arns:
            _absent_ok(lambda p=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=p), "NoSuchEntity")
        _absent_ok(lambda: iam.delete_role(RoleName=name), "NoSuchEntity")

    ctx.on_cleanup(_cleanup)
    return arn


def _create_pod_identity_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-podid-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "pods.eks.amazonaws.com"},
                    "Action": ["sts:AssumeRole", "sts:TagSession"],
                }
            ],
        }
    )
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _absent_ok(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_cluster_with_retry(ctx, name, role_arn, subnet_ids, timeout_s=90):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            return
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code in ("InvalidParameterException", "ClientException"):
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"create_cluster never succeeded (IAM propagation?): {last_err}")


def _wait_cluster_status(ctx, name, target_statuses, timeout_s, interval_s=15):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} status {last} never reached {target_statuses}")


def _wait_cluster_deleted(ctx, name, timeout_s, interval_s=15):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _wait_nodegroup_status(ctx, cluster_name, nodegroup_name, target_statuses, timeout_s, interval_s=15):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]["status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} status {last} never reached {target_statuses}")


def _wait_nodegroup_deleted(ctx, cluster_name, nodegroup_name, timeout_s, interval_s=15):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} was not deleted within {timeout_s}s")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaked the
# VPC while the check PASSED. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes.
_NET_TEARDOWN_S = 1260.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}


def _delete_net(client, run_state: dict, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    deadline = run_state.setdefault("net", _time.monotonic() + _NET_TEARDOWN_S)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
