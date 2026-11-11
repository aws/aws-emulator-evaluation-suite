"""cluster-delete-blocked-by-dependents-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-delete-blocked-by-dependents-rejected"
GROUP = "state-machine"
SERVICES = ["eks"]

# Upper bound for the cluster-gone wait: the per-check timeout, not an assertion on elapsed time.
_SUITE_BUDGET_S = 3600


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster is rejected with ResourceInUseException while a Fargate profile is attached
    (the cluster is not mutated), and succeeds -- ending gone, unlisted and unusable -- only after
    that dependent Fargate profile is removed."""
    eks = ctx.client("eks")
    cluster_name, vpc_id = _create_active_cluster(ctx)
    pod_exec_role_arn = _create_fargate_pod_execution_role(ctx)
    private_subnet_id = _create_private_fargate_subnet(ctx, vpc_id)
    fargate_profile_name = ctx.unique_name("sim2real-fp-")

    _create_fargate_profile_with_retry(
        eks, cluster_name, fargate_profile_name, pod_exec_role_arn, private_subnet_id
    )
    ctx.on_cleanup(lambda: _best_effort_delete_fargate_profile(eks, cluster_name, fargate_profile_name))
    fargate_profile = _poll_until(
        lambda: eks.describe_fargate_profile(clusterName=cluster_name, fargateProfileName=fargate_profile_name)[
            "fargateProfile"
        ],
        lambda fp: fp["status"] in ("ACTIVE", "CREATE_FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=2.0,
    )
    assert fargate_profile["status"] == "ACTIVE", (
        f"the dependent must actually be ACTIVE for the refusal below to test what this check "
        f"claims to test, not CREATE_FAILED; got {fargate_profile['status']!r}"
    )

    # A Fargate profile (not a managed nodegroup) is the dependent: it has no EC2 instances, so it
    # creates and deletes fast enough to fit the per-check timeout.
    # Negative: DeleteCluster must be refused while the Fargate profile dependent still exists.
    delete_code, delete_status, delete_message = _error(lambda: eks.delete_cluster(name=cluster_name))
    assert delete_code == "ResourceInUseException", delete_code
    assert delete_status == 409, f"expected HTTP 409 for the refused DeleteCluster, got {delete_status}"
    expected_message = "Cluster has Fargate Profiles in ACTIVE/CREATING state"
    assert delete_message == expected_message, f"expected the message {expected_message!r}, got {delete_message!r}"
    still_active = eks.describe_cluster(name=cluster_name)["cluster"]
    assert still_active["status"] == "ACTIVE", "the refused delete must not have mutated the cluster"
    assert cluster_name in _listed_clusters(eks), (
        f"{cluster_name} must still be listed after the refused delete"
    )

    eks.delete_fargate_profile(clusterName=cluster_name, fargateProfileName=fargate_profile_name)
    _wait_deleted(
        lambda: eks.describe_fargate_profile(clusterName=cluster_name, fargateProfileName=fargate_profile_name),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=2.0,
    )

    # Positive control: with no dependents left, DeleteCluster now succeeds.
    deleted = eks.delete_cluster(name=cluster_name)["cluster"]
    assert deleted["name"] == cluster_name, f"DeleteCluster answered for {deleted['name']!r}"

    _wait_deleted(
        lambda: eks.describe_cluster(name=cluster_name),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _SUITE_BUDGET_S),
        interval_s=2.0,
    )
    not_found_code, not_found_status, not_found_message = _error(lambda: eks.describe_cluster(name=cluster_name))
    assert not_found_code == "ResourceNotFoundException", not_found_code
    assert not_found_status == 404, f"expected HTTP 404 describing the deleted cluster, got {not_found_status}"
    # AWS words this with and without a closing period.
    assert re.fullmatch(rf"No cluster found for name: {re.escape(cluster_name)}\.?", not_found_message), (
        f"expected 'No cluster found for name: {cluster_name}', got {not_found_message!r}"
    )
    # ListClusters lags DescribeCluster's not-found; the cluster must drop out of the list.
    _poll_until(
        lambda: _listed_clusters(eks),
        lambda names: cluster_name not in names,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=2.0,
    )
    dead_code, dead_status, message = _error(
        lambda: eks.update_cluster_config(name=cluster_name, resourcesVpcConfig={"endpointPublicAccess": True})
    )
    assert dead_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating the deleted cluster, got {dead_code}"
    )
    assert dead_status == 404, f"expected HTTP 404 updating the deleted cluster, got {dead_status}"
    assert re.fullmatch(rf"No cluster found for name: {re.escape(cluster_name)}\.?", message), (
        f"expected 'No cluster found for name: {cluster_name}', got {message!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return (
            e.response["Error"]["Code"],
            e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            e.response["Error"].get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _listed_clusters(eks):
    return [n for page in eks.get_paginator("list_clusters").paginate() for n in page["clusters"]]


def _create_fargate_profile_with_retry(
    eks, cluster_name, fargate_profile_name, pod_exec_role_arn, subnet_id, attempts=50, delay_s=2
):
    """A just-created pod execution role's trust policy or the cluster role's policies may not yet
    be visible to EKS (IAM is eventually consistent), so a correct call can fail with
    InvalidParameterException or a missing-permissions InvalidRequestException; retry (bounded)."""
    last_err = None
    for _ in range(attempts):
        try:
            eks.create_fargate_profile(
                clusterName=cluster_name,
                fargateProfileName=fargate_profile_name,
                podExecutionRoleArn=pod_exec_role_arn,
                subnets=[subnet_id],
                selectors=[{"namespace": "default"}],
            )
            return
        except ClientError as e:
            last_err = e
            code = e.response["Error"]["Code"]
            if (code == "InvalidParameterException" and "Trust Policy" in str(e)) or (
                code == "InvalidRequestException" and "Missing permissions" in str(e)
            ):
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=600.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _wait_deleted(describe_fn, timeout_s=900.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            describe_fn()
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the resource being deleted: the run budget ended first; not graded")
    raise AssertionError(f"resource still present after {timeout_s}s")


def _retry_delete(fn, attempts=100, delay_s=3):
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if "NotFound" in code:
                return
            if i == attempts - 1:
                raise
            time.sleep(delay_s)


def _best_effort_delete_fargate_profile(eks, cluster_name, fargate_profile_name):
    try:
        eks.delete_fargate_profile(clusterName=cluster_name, fargateProfileName=fargate_profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    _wait_deleted(
        lambda: eks.describe_fargate_profile(clusterName=cluster_name, fargateProfileName=fargate_profile_name),
        timeout_s=300.0,
        interval_s=2.0,
    )


def _create_vpc_infra(ctx):
    ec2 = ctx.client("ec2")
    # The check builds its own network: the cluster's public subnets and (below) the private
    # Fargate subnet all live in this VPC, so the account's default VPC is never modified.
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:2]]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.82.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-igw-")}]}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _teardown_igw():
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        _retry_delete(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))

    ctx.on_cleanup(_teardown_igw)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-rt-")}]}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.82.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-subnet{i}-")}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=aid)))
        subnet_ids.append(subnet_id)
    return subnet_ids, vpc_id


def _pick_free_cidr(vpc_cidr, used_cidrs, prefix_len=24):
    import ipaddress

    net = ipaddress.ip_network(vpc_cidr)
    used_nets = [ipaddress.ip_network(c) for c in used_cidrs]
    for candidate in net.subnets(new_prefix=prefix_len):
        if not any(candidate.overlaps(u) for u in used_nets):
            return str(candidate)
    raise RuntimeError(f"no free /{prefix_len} CIDR block available in {vpc_cidr}")


def _create_private_fargate_subnet(ctx, vpc_id):
    """A single PRIVATE subnet (no route to an Internet Gateway) in the check's own VPC from
    ``_create_vpc_infra``. Fargate profile subnets are required to have no direct IGW route --
    CreateFargateProfile rejects the public subnets ``_create_vpc_infra`` returns."""
    ec2 = ctx.client("ec2")
    vpc_cidr = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["CidrBlock"]
    existing = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    used_cidrs = [s["CidrBlock"] for s in existing]
    az = (
        existing[0]["AvailabilityZone"]
        if existing
        else ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ][0]["ZoneName"]
    )
    cidr = _pick_free_cidr(vpc_cidr, used_cidrs, prefix_len=24)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr,
        AvailabilityZone=az,
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-fg-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-fg-rt-")}]}
        ],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id)))
    # Deliberately NO route to an Internet Gateway here -- Fargate profile subnets must not have one.
    assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=assoc_id)))
    return subnet_id


def _create_role(ctx, trust_principal, actions, managed_policies=()):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_principal}, "Action": actions}],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in managed_policies:
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        _retry_delete(lambda: iam.delete_role(RoleName=name), attempts=10, delay_s=2)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_fargate_pod_execution_role(ctx):
    return _create_role(
        ctx,
        "eks-fargate-pods.amazonaws.com",
        "sts:AssumeRole",
        managed_policies=["arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"],
    )


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    subnet_ids, vpc_id = _create_vpc_infra(ctx)
    role_arn = _create_role(
        ctx, "eks.amazonaws.com", "sts:AssumeRole",
        managed_policies=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
    )
    cluster_name = ctx.unique_name("sim2real-eks-cluster-")

    def _create():
        return eks.create_cluster(
            name=cluster_name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids, "endpointPublicAccess": True, "endpointPrivateAccess": False},
        )

    deadline = time.monotonic() + _budget_s(ctx, 80.0)
    while True:
        try:
            _create()
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in ("ClientException", "InvalidParameterException") and (
                time.monotonic() < deadline
            ):
                time.sleep(2)
                continue
            if e.response["Error"]["Code"] in ("ClientException", "InvalidParameterException") and _budget_spent(ctx):
                raise TimeoutError(f"CreateCluster {cluster_name} past IAM propagation: the run budget ended first; not graded") from e
            raise

    ctx.on_cleanup(lambda: _retry_delete(lambda: eks.delete_cluster(name=cluster_name)))

    _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"],
        lambda c: c["status"] == "ACTIVE",
        ctx=ctx,
        timeout_s=_budget_s(ctx, 1200.0),
        interval_s=2.0,
    )
    return cluster_name, vpc_id


# A load balancer, endpoint, cluster, function or instance in this VPC deletes asynchronously: its
# ENIs linger, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with
# DependencyViolation, and swallowing that would leak the VPC. So wait (bounded) for the ENIs,
# retry DependencyViolation in that window, then raise naming the ENIs still attached.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
