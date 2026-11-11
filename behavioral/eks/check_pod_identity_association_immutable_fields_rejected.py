"""pod-identity-association-immutable-fields-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-association-immutable-fields-rejected"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A duplicate namespace/serviceAccount pod identity association is ResourceInUseException.

    Only roleArn is updatable; moving namespaces needs delete+recreate, after which the old id is
    ResourceNotFoundException for read and update, and the replacement gets a new associationId.
    """
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

    # Negative: duplicate namespace/serviceAccount is a conflict, and the original is untouched.
    dup_code, dup_msg = _error_code(
        lambda: eks.create_pod_identity_association(
            clusterName=cluster_name,
            namespace=namespace,
            serviceAccount=service_account,
            roleArn=role_arn_2,
        )
    )
    assert dup_code == "ResourceInUseException", dup_code
    assert dup_msg == f"The service account is already associated with a different IAM role: {role_arn_1}", dup_msg
    still_original = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert still_original["roleArn"] == role_arn_1, "duplicate-create attempt must not mutate the existing association"
    listed = eks.list_pod_identity_associations(clusterName=cluster_name)["associations"]
    same_pair = [a for a in listed if a["namespace"] == namespace and a["serviceAccount"] == service_account]
    assert len(same_pair) == 1, "no second association should have been created for the same namespace/serviceAccount"

    # Positive control: the mutable roleArn field updates normally on the very same association.
    eks.update_pod_identity_association(
        clusterName=cluster_name, associationId=association_id, roleArn=role_arn_2
    )
    after = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert after["roleArn"] == role_arn_2
    assert after["associationId"] == association_id
    assert after["namespace"] == namespace
    assert after["serviceAccount"] == service_account

    # UpdatePodIdentityAssociation has no namespace parameter, so a move is delete + recreate.
    eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    gone_msg = f"No service account role association found for ID: {association_id}"
    gone_code, gone_text = _error_code(
        lambda: eks.describe_pod_identity_association(
            clusterName=cluster_name, associationId=association_id
        )
    )
    assert gone_code == "ResourceNotFoundException", gone_code
    assert gone_text == gone_msg, gone_text
    dead_update_code, dead_update_text = _error_code(
        lambda: eks.update_pod_identity_association(
            clusterName=cluster_name, associationId=association_id, roleArn=role_arn_1
        )
    )
    assert dead_update_code == "ResourceNotFoundException", dead_update_code
    assert dead_update_text == gone_msg, dead_update_text

    recreated = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace="kube-system",
        serviceAccount=service_account,
        roleArn=role_arn_2,
    )["association"]
    recreated_id = recreated["associationId"]
    ctx.on_cleanup(lambda: _best_effort_delete_assoc(eks, cluster_name, recreated_id))
    assert recreated_id != association_id, "the replacement must get a brand-new associationId"

    verified = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=recreated_id
    )["association"]
    assert verified["associationId"] == recreated_id
    assert verified["namespace"] == "kube-system"


def _error_code(fn):
    """Call fn(); return its (error code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


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
        CidrBlock="10.80.0.0/16",
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
            CidrBlock=f"10.80.{i}.0/24",
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
