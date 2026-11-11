"""pod-identity-association-untrusted-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-association-untrusted-role-rejected"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePodIdentityAssociation rejects a roleArn whose trust policy does not permit
    pods.eks.amazonaws.com and leaves no association behind, while a correctly trusted role on the
    same cluster succeeds."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    # --- negative: role trusts only ec2.amazonaws.com, not pods.eks.amazonaws.com ---
    untrusted_role_arn = _create_untrusted_role(ctx)
    bad_namespace = "default"
    bad_sa = ctx.unique_name("sim2real-sa-bad-")

    code, message = _client_error(
        lambda: eks.create_pod_identity_association(
            clusterName=cluster["name"],
            namespace=bad_namespace,
            serviceAccount=bad_sa,
            roleArn=untrusted_role_arn,
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == (
        "Trust policy of the role provided is invalid. Follow the official documentation to resolve the issue."
    ), message

    remaining = eks.list_pod_identity_associations(
        clusterName=cluster["name"], namespace=bad_namespace, serviceAccount=bad_sa
    )["associations"]
    assert remaining == [], remaining

    # --- positive control: role that DOES trust pods.eks.amazonaws.com succeeds ---
    good_role_arn = _create_trusted_role(ctx)
    good_namespace = "default"
    good_sa = ctx.unique_name("sim2real-sa-good-")
    eks.create_pod_identity_association(
        clusterName=cluster["name"], namespace=good_namespace, serviceAccount=good_sa, roleArn=good_role_arn
    )
    created = eks.list_pod_identity_associations(
        clusterName=cluster["name"], namespace=good_namespace, serviceAccount=good_sa
    )["associations"]
    assert len(created) == 1, created

    # ListPodIdentityAssociations returns summaries only (no roleArn); confirm the role via an
    # independent DescribePodIdentityAssociation read.
    described = eks.describe_pod_identity_association(
        clusterName=cluster["name"], associationId=created[0]["associationId"]
    )["association"]
    assert described["roleArn"] == good_role_arn, described


# ===== helpers =====
def _client_error(fn):
    """Call fn, require that it raises ClientError, return (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last}")


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


def _create_vpc_infra(ctx):
    """Self-provisioned VPC/subnets: a freshly provisioned account may have no default VPC."""
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
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


def _create_role(ctx, name_prefix, trust_principal, actions, managed_policies=()):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_principal}, "Action": actions}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # Bounded wait for the role to become readable via IAM's own API, not a blind sleep:
    # newly-created roles can lag briefly before other services can resolve them.
    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"],
        lambda arn: arn == role["Arn"],
        timeout_s=30.0,
        interval_s=2.0,
    )

    def _cleanup():
        for policy_arn in managed_policies:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        _retry_delete(lambda: iam.delete_role(RoleName=role_name), attempts=5, delay_s=5)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnet_ids = _create_vpc_infra(ctx)
    role_arn = _create_role(
        ctx, "sim2real-eks-clusterrole-", "eks.amazonaws.com", "sts:AssumeRole",
        managed_policies=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
    )

    # The just-created role is rejected until IAM propagates it: retry every 2 s up to 80 s,
    # capped by the run's remaining time.
    retry_deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        retry_deadline = min(retry_deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as e:
            if (
                e.response["Error"]["Code"] not in ("ClientException", "InvalidParameterException")
                or time.monotonic() >= retry_deadline
            ):
                raise
        time.sleep(2)

    ctx.on_cleanup(lambda: _retry_delete(lambda: eks.delete_cluster(name=name)))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster did not reach ACTIVE: {cluster['status']}")
    return {"name": name, "arn": cluster["arn"], "role_arn": role_arn, "subnet_ids": subnet_ids}


def _create_untrusted_role(ctx):
    return _create_role(ctx, "sim2real-eks-untrusted-", "ec2.amazonaws.com", "sts:AssumeRole")


def _create_trusted_role(ctx):
    return _create_role(
        ctx, "sim2real-eks-trusted-", "pods.eks.amazonaws.com", ["sts:AssumeRole", "sts:TagSession"]
    )


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
