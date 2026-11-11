"""pod-identity-association-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PodIdentityAssociation keeps a stable associationId across UpdatePodIdentityAssociation
    (only roleArn/targetRoleArn/disableSessionTags mutate), and 404s (ResourceNotFoundException)
    from Describe/List after DeletePodIdentityAssociation."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    role_arn_1 = _create_pod_identity_role(ctx)
    role_arn_2 = _create_pod_identity_role(ctx)

    namespace = "default"
    service_account = ctx.unique_name("sim2real-sa-")[:63]

    created = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace=namespace,
        serviceAccount=service_account,
        roleArn=role_arn_1,
    )["association"]
    association_id = created["associationId"]
    ctx.on_cleanup(lambda: _best_effort_delete_assoc(eks, cluster_name, association_id))
    assert created["clusterName"] == cluster_name, f"expected clusterName={cluster_name!r}, got {created['clusterName']!r}"
    assert created["namespace"] == namespace, f"expected namespace={namespace!r}, got {created['namespace']!r}"
    assert created["serviceAccount"] == service_account, f"expected serviceAccount={service_account!r}, got {created['serviceAccount']!r}"
    assert created["roleArn"] == role_arn_1, f"expected roleArn={role_arn_1!r}, got {created['roleArn']!r}"

    described = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert described["associationId"] == association_id, f"expected associationId={association_id!r}, got {described['associationId']!r}"
    assert described["roleArn"] == role_arn_1, f"expected roleArn={role_arn_1!r}, got {described['roleArn']!r}"

    updated = eks.update_pod_identity_association(
        clusterName=cluster_name, associationId=association_id, roleArn=role_arn_2
    )["association"]
    assert updated["associationId"] == association_id, "associationId must stay stable across update"
    assert updated["roleArn"] == role_arn_2, f"expected roleArn={role_arn_2!r} in the update response, got {updated['roleArn']!r}"

    described_after_update = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert described_after_update["associationId"] == association_id, f"expected associationId={association_id!r}, got {described_after_update['associationId']!r}"
    assert described_after_update["roleArn"] == role_arn_2, f"expected roleArn={role_arn_2!r} on independent describe after update, got {described_after_update['roleArn']!r}"
    assert described_after_update["namespace"] == namespace, "namespace is immutable across update"
    assert described_after_update["serviceAccount"] == service_account, "serviceAccount is immutable across update"
    assert described_after_update["clusterName"] == cluster_name, f"expected clusterName={cluster_name!r}, got {described_after_update['clusterName']!r}"

    listed = eks.list_pod_identity_associations(clusterName=cluster_name)["associations"]
    matching = [a for a in listed if a["associationId"] == association_id]
    assert len(matching) == 1, f"expected exactly 1 listed association with id={association_id!r}, got {len(matching)}"
    assert matching[0]["namespace"] == namespace, f"expected namespace={namespace!r} in list entry, got {matching[0]['namespace']!r}"
    assert matching[0]["serviceAccount"] == service_account, f"expected serviceAccount={service_account!r} in list entry, got {matching[0]['serviceAccount']!r}"

    eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)

    gone_msg = f"No service account role association found for ID: {association_id}"
    not_found_code, not_found_msg = _error_code(
        lambda: eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    )
    assert not_found_code == "ResourceNotFoundException", f"expected ResourceNotFoundException on describe after delete, got {not_found_code!r}"
    assert not_found_msg == gone_msg, f"describe after delete -> {not_found_msg!r}"

    remaining = eks.list_pod_identity_associations(clusterName=cluster_name)["associations"]
    assert association_id not in {a["associationId"] for a in remaining}, f"deleted associationId={association_id!r} still present in list_pod_identity_associations"

    update_after_delete_code, update_after_delete_msg = _error_code(
        lambda: eks.update_pod_identity_association(
            clusterName=cluster_name, associationId=association_id, roleArn=role_arn_1
        )
    )
    assert update_after_delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException when updating a deleted associationId={association_id!r}, "
        f"got {update_after_delete_code!r}"
    )
    assert update_after_delete_msg == gone_msg, f"update after delete -> {update_after_delete_msg!r}"


# ===== helpers =====


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _poll_until(probe, predicate, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _retry_delete(fn, attempts=20, delay_s=15):
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


def _best_effort_delete_assoc(eks, cluster_name, association_id):
    try:
        eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_vpc_infra(ctx):
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:2]]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.79.0.0/16",
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
            CidrBlock=f"10.79.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-subnet{i}-")}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=aid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


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
        _retry_delete(lambda: iam.delete_role(RoleName=name), attempts=5, delay_s=5)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_pod_identity_role(ctx):
    return _create_role(ctx, "pods.eks.amazonaws.com", ["sts:AssumeRole", "sts:TagSession"])


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    subnet_ids = _create_vpc_infra(ctx)
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

    # The just-created role is rejected until IAM propagates it: retry every 2 s up to 80 s,
    # capped by the run's remaining time.
    retry_deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        retry_deadline = min(retry_deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            _create()
            break
        except ClientError as e:
            if (
                e.response["Error"]["Code"] not in ("ClientException", "InvalidParameterException")
                or time.monotonic() >= retry_deadline
            ):
                raise
        time.sleep(2)

    ctx.on_cleanup(lambda: _retry_delete(lambda: eks.delete_cluster(name=cluster_name)))

    _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"],
        lambda c: c["status"] == "ACTIVE",
        timeout_s=1200.0,
        interval_s=20.0,
    )
    return cluster_name


# A cluster or other resource in this VPC deletes asynchronously and leaves its ENIs behind for a while,
# so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for the ENIs, retries DependencyViolation in one window shared by the check's network
# deletes, then raises naming any ENIs still attached. Teardown-only: run() never calls this.
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
