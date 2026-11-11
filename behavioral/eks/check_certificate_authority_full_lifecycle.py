"""certificate-authority-full-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "certificate-authority-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created successor CA starts NOT_USED; activating it makes it IN_USE and retires the original
    to NOT_USED; deleting the original drops it from ListCertificateAuthorities and 404s describe.

    Reference: https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateCertificateAuthority.html
    Reference: https://docs.aws.amazon.com/eks/latest/APIReference/API_ActivateCertificateAuthority.html
    Reference: https://docs.aws.amazon.com/eks/latest/APIReference/API_DeleteCertificateAuthority.html
    """
    eks = ctx.client("eks")
    cluster = _ensure_active_cluster(ctx)
    name = cluster["name"]

    baseline = eks.list_certificate_authorities(clusterName=name)["certificateAuthorities"]
    assert len(baseline) == 1, f"expected exactly one CA on a freshly created cluster, got {baseline}"
    original = baseline[0]
    assert original["signingStatus"] == "IN_USE"

    create_resp = eks.create_certificate_authority(clusterName=name)
    successor_id = create_resp["certificateAuthority"]["id"]
    assert create_resp["certificateAuthority"]["signingStatus"] == "NOT_USED"

    successor = _wait_ca_distribution_complete(ctx, name, successor_id)
    assert successor["distributionStatus"] == "COMPLETE"

    activate_resp = eks.activate_certificate_authority(
        clusterName=name, certificateAuthorityId=successor_id
    )
    activate_update = _wait_update_terminal(ctx, name, activate_resp["update"]["id"])
    assert activate_update["status"] == "Successful"

    successor_after = eks.describe_certificate_authority(
        clusterName=name, certificateAuthorityId=successor_id
    )["certificateAuthority"]
    assert successor_after["signingStatus"] == "IN_USE"

    original_after = eks.describe_certificate_authority(
        clusterName=name, certificateAuthorityId=original["id"]
    )["certificateAuthority"]
    assert original_after["signingStatus"] == "NOT_USED"

    delete_resp = eks.delete_certificate_authority(
        clusterName=name, certificateAuthorityId=original["id"]
    )
    delete_update = _wait_update_terminal(ctx, name, delete_resp["update"]["id"])
    assert delete_update["status"] == "Successful"

    code, message = _error(
        lambda: eks.describe_certificate_authority(
            clusterName=name, certificateAuthorityId=original["id"]
        )
    )
    assert code == "ResourceNotFoundException"
    # The message embeds a backend request id the check never sees; its fixed text is asserted.
    assert message.startswith(
        "certificate authority not found (Service: EksCertificateAuthority, Status Code: 404, Request ID: "
    ) and message.endswith(") (SDK Attempt Count: 1)"), message

    remaining_ids = {
        ca["id"] for ca in eks.list_certificate_authorities(clusterName=name)["certificateAuthorities"]
    }
    assert original["id"] not in remaining_ids
    assert successor_id in remaining_ids


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_ca_distribution_complete(ctx, cluster_name: str, ca_id: str, timeout_s: float = 1500.0):
    eks = ctx.client("eks")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    ca: dict[str, Any] = {}
    while time.monotonic() < deadline:
        ca = eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=ca_id
        )["certificateAuthority"]
        if ca["distributionStatus"] in ("COMPLETE", "FAILED"):
            return ca
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"CA {ca_id} distributionStatus reaching COMPLETE/FAILED: the run budget ended first; not graded")
    raise AssertionError(f"CA {ca_id} distributionStatus never reached COMPLETE/FAILED: {ca}")


def _wait_update_terminal(ctx, cluster_name: str, update_id: str, timeout_s: float = 600.0):
    eks = ctx.client("eks")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    update: dict[str, Any] = {}
    while time.monotonic() < deadline:
        update = eks.describe_update(name=cluster_name, updateId=update_id)["update"]
        if update["status"] in ("Successful", "Failed", "Cancelled"):
            return update
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"update {update_id} reaching a terminal state: the run budget ended first; not graded")
    raise AssertionError(f"update {update_id} did not reach a terminal state within {timeout_s}s")


def _retry_delete(fn, attempts=100, delay_s=3):
    from botocore.exceptions import ClientError

    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as e:
            if "NotFound" in e.response["Error"]["Code"]:
                return
            if i == attempts - 1:
                raise
            time.sleep(delay_s)


def _resolve_subnet_ids(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        adopted = list(by_az.values())[:3]
        if len(adopted) >= 2:
            return adopted
    return _create_vpc_infra(ctx)


def _create_vpc_infra(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:2]]
    if len(az_names) < 2:
        raise AssertionError(f"region has fewer than 2 available AZs required to create an EKS cluster: {azs}")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
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
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-subnet{i}-")}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=aid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _ensure_active_cluster(ctx) -> dict[str, str]:
    import json

    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    eks = ctx.client("eks")

    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    subnet_ids = _resolve_subnet_ids(ctx)

    cluster_name = ctx.unique_name("sim2real-eks-")
    create_deadline = time.monotonic() + _budget_s(ctx, 80.0)
    while True:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterException" and time.monotonic() < create_deadline:
                time.sleep(2)
                continue
            if code == "InvalidParameterException" and _budget_spent(ctx):
                raise TimeoutError(f"CreateCluster {cluster_name} past IAM propagation: the run budget ended first; not graded") from exc
            raise

    def _cleanup_cluster():
        try:
            eks.delete_cluster(name=cluster_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        deadline = time.monotonic() + 15 * 60
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=cluster_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(3)

    ctx.on_cleanup(_cleanup_cluster)

    deadline = time.monotonic() + _budget_s(ctx, 25 * 60)
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=cluster_name)["cluster"]
        if desc["status"] == "ACTIVE":
            return {"name": cluster_name, "arn": desc["arn"], "role_arn": role_arn, "version": desc["version"]}
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {cluster_name} entered FAILED state while creating: {desc}")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_name} ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"cluster {cluster_name} did not become ACTIVE within timeout: {desc}")


# A resource in this VPC deletes asynchronously and its ENIs linger, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for the ENIs to go,
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
