"""concurrent-certificate-authority-delete-during-activation-conflict."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "concurrent-certificate-authority-delete-during-activation-conflict"
GROUP = "concurrency"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a CA while its activation update is in flight fails with ResourceInUseException
    and the exact "currently has update <id> in progress" message; with no update in flight a
    successor deletes cleanly, and the activation still succeeds with the CA left intact."""
    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _vpc_subnets(ctx)
    _create_cluster_with_retry(ctx, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_name))
    cluster = _wait_cluster_status(ctx, cluster_name, {"ACTIVE", "FAILED"})
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster['status']}")

    # Positive control: a successor with no update in flight deletes cleanly. CreateCertificateAuthority
    # starts its own update, and deleting before it settles raises the same ResourceInUseException
    # as the race below, so wait for it. Deleting also frees the cluster's one successor slot.
    create_a = eks.create_certificate_authority(clusterName=cluster_name)
    ca_a_id = create_a["certificateAuthority"]["id"]
    _wait_update_successful(ctx, eks, cluster_name, create_a["update"]["id"])
    delete_a = eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_a_id)
    _wait_update_successful(ctx, eks, cluster_name, delete_a["update"]["id"])
    _poll_until(
        lambda: _ca_exists(eks, cluster_name, ca_a_id),
        lambda exists: not exists,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=2.0,
    )

    # Wait for the create's update so the activation is the only update in flight.
    # ActivateCertificateAuthority before distributionStatus is COMPLETE raises
    # InvalidRequestException, so wait for that too.
    create_b = eks.create_certificate_authority(clusterName=cluster_name)
    ca_b_id = create_b["certificateAuthority"]["id"]
    _wait_update_successful(ctx, eks, cluster_name, create_b["update"]["id"])
    _wait_ca_distribution_complete(ctx, eks, cluster_name, ca_b_id)

    activate_resp = eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_b_id)
    assert activate_resp["update"]["status"] == "InProgress", (
        f"expected ActivateCertificateAuthority to return an in-progress update, got {activate_resp['update']!r}"
    )
    activate_update_id = activate_resp["update"]["id"]
    mid_flight = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=ca_b_id
    )["certificateAuthority"]
    assert mid_flight["signingStatus"] == "ACTIVATING", (
        f"expected ca_b's own signingStatus to read ACTIVATING while its activation update is in "
        f"flight, got {mid_flight['signingStatus']!r}"
    )

    delete_code, delete_message = _error(
        lambda: eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_b_id)
    )
    assert delete_code == "ResourceInUseException", f"expected ResourceInUseException, got {delete_code!r}"
    assert delete_message == (
        f"Cannot CertificateAuthorityUpdate because cluster {cluster_name} "
        f"currently has update {activate_update_id} in progress"
    ), f"unexpected message: {delete_message!r}"

    _wait_update_successful(ctx, eks, cluster_name, activate_update_id, timeout_s=1800.0, interval_s=2.0)

    still_there = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=ca_b_id
    )["certificateAuthority"]
    assert still_there["id"] == ca_b_id, f"expected ca_b {ca_b_id} to still exist, got {still_there['id']!r}"


from botocore.exceptions import ClientError  # noqa: E402


def _tag_spec(resource_type, name):
    return [{
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real-managed", "Value": "true"}],
    }]


def _error(fn):
    """Run fn, which must fail; return the (code, message) AWS sent."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("call succeeded but was expected to fail")


def _ca_exists(eks, cluster_name, ca_id):
    try:
        eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return True


def _wait_update_successful(ctx, eks, cluster_name, update_id, timeout_s=600.0, interval_s=2.0):
    """Block until the update settles; a cluster allows one CA update in flight at a time."""
    update = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=interval_s,
    )
    if update["status"] != "Successful":
        raise AssertionError(f"update {update_id} ended in {update['status']}, expected Successful")
    return update


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError("the polled condition: the run budget ended first; not graded")
            raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _wait_ca_distribution_complete(ctx, eks, cluster_name, ca_id, timeout_s=1800.0, interval_s=2.0):
    return _poll_until(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=ca_id
        )["certificateAuthority"],
        lambda c: c["distributionStatus"] == "COMPLETE",
        ctx=ctx,
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=interval_s,
    )


def _vpc_subnets(ctx):
    """Provision a dedicated VPC/IGW/route-table/subnets across two AZs for the cluster."""
    ec2 = ctx.client("ec2")
    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ][:2]
    ]
    if len(azs) < 2:
        raise AssertionError("region lacks 2 available AZs to provision an EKS cluster")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.79.0.0/16",
        TagSpecifications=_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-")),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_tag_spec("internet-gateway", ctx.unique_name("sim2real-eks-igw-"))
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _detach_and_delete_igw():
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)

    ctx.on_cleanup(_detach_and_delete_igw)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=_tag_spec("route-table", ctx.unique_name("sim2real-eks-rt-")),
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.79.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-sn{i}-")),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: ec2.disassociate_route_table(AssociationId=aid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_cluster_with_retry(ctx, name, role_arn, subnet_ids, **kwargs):
    eks = ctx.client("eks")
    deadline = time.monotonic() + _budget_s(ctx, 80.0)
    while True:
        try:
            return eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real-managed": "true"},
                **kwargs,
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code == "ClientException" and "not authorized" in message:
                if time.monotonic() < deadline:
                    time.sleep(2)
                    continue
                if _budget_spent(ctx):
                    raise TimeoutError("create_cluster once the cluster role propagates: the run "
                                       "budget ended first; not graded") from err
            raise


def _wait_cluster_status(ctx, name, statuses, timeout_s=1200.0, interval_s=2.0):
    eks = ctx.client("eks")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    cluster = None
    while True:
        cluster = eks.describe_cluster(name=name)["cluster"]
        if cluster["status"] in statuses:
            return cluster
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"cluster {name} reaching {statuses}: the run budget ended first; not graded")
            raise AssertionError(
                f"cluster {name} did not reach {statuses} within {timeout_s}s "
                f"(last={cluster['status']})"
            )
        time.sleep(interval_s)


def _delete_cluster(ctx, name):
    eks = ctx.client("eks")
    try:
        eks.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 900.0
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3.0)


# EC2 network teardown waits for AWS-managed ENIs to leave before deleting: dependents in the VPC
# delete asynchronously, so an immediate DeleteSubnet/DeleteVpc fails with DependencyViolation.
# The bounded window is shared by all of one check's network deletes and fits the cleanup budget.
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
