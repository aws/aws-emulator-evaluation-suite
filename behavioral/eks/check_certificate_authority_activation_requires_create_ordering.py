"""certificate-authority-activation-requires-create-ordering."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "certificate-authority-activation-requires-create-ordering"
GROUP = "ordering"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ActivateCertificateAuthority on a never-created CA id fails with ResourceNotFoundException and AWS's
    exact "not in the trusted list" message, while create, distribution and then activate of a real
    successor returns an InProgress update for that CA that ends Successful.
    """
    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _create_own_subnets(ctx)
    _create_cluster_with_retry(ctx, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_name))
    cluster = _wait_cluster_status(ctx, cluster_name, {"ACTIVE", "FAILED"})
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster['status']}")

    # Activating an id that no CreateCertificateAuthority ever produced is rejected.
    bogus_ca_id = f"csa-{uuid.uuid4().hex[:16]}"
    code, message = _error(
        lambda: eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=bogus_ca_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == (
        f"Certificate authority {bogus_ca_id} is not in the trusted list for cluster {cluster_name}"
    ), f"unexpected message: {message!r}"

    # Properly ordered: create first, wait for distribution, then activate succeeds.
    ca_id = eks.create_certificate_authority(clusterName=cluster_name)["certificateAuthority"]["id"]
    _wait_ca_distribution_complete(ctx, cluster_name, ca_id)

    activate_resp = eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
    assert activate_resp["update"]["status"] == "InProgress", activate_resp["update"]
    assert activate_resp["certificateAuthority"]["id"] == ca_id
    activate_status = _wait_update_terminal(ctx, cluster_name, activate_resp["update"]["id"], timeout_s=1800)
    assert activate_status == "Successful", f"activation update ended in {activate_status!r}, not Successful"


from botocore.exceptions import ClientError  # noqa: E402


def _error(fn):
    """Run fn, which must fail; return the (code, message) AWS sent."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("call succeeded but was expected to fail")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _create_own_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-eks-caord-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.63.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc(ec2, vpc_id))

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "zone-type", "Values": ["availability-zone"]},
                {"Name": "state", "Values": ["available"]},
            ]
        )["AvailabilityZones"]
    ][:2]
    if len(azs) < 2:
        raise AssertionError(f"region does not have at least 2 available availability zones, found {len(azs)}")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_name = ctx.unique_name("sim2real-eks-caord-subnet-")
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.63.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe_delete_subnet(ec2, sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _safe_delete_subnet(ec2, subnet_id: str) -> None:
    """Delete the subnet; an already-deleted one is fine, any other failure raises."""
    try:
        _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _safe_delete_vpc(ec2, vpc_id: str) -> None:
    """Delete the VPC; an already-deleted one is fine, any other failure raises."""
    try:
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_cluster_with_retry(ctx, name, role_arn, subnet_ids, **kwargs):
    eks = ctx.client("eks")
    # A fresh cluster role is refused as "not authorized" until IAM propagates it.
    left = ctx.time_left()
    deadline = time.monotonic() + (80.0 if left is None else min(80.0, left))
    while True:
        try:
            return eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                **kwargs,
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code == "ClientException" and "not authorized" in message and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _wait_cluster_status(ctx, name, statuses, timeout_s=1200.0, interval_s=20.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    cluster = None
    while True:
        cluster = eks.describe_cluster(name=name)["cluster"]
        if cluster["status"] in statuses:
            return cluster
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"cluster {name} did not reach {statuses} within {timeout_s}s "
                f"(last={cluster['status']})"
            )
        time.sleep(interval_s)


def _wait_ca_distribution_complete(ctx, cluster_name, ca_id, timeout_s=1800.0, interval_s=20.0):
    eks = ctx.client("eks")
    return _poll_until(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=ca_id
        )["certificateAuthority"],
        lambda c: c["distributionStatus"] == "COMPLETE",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


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
        time.sleep(15.0)


def _wait_update_terminal(ctx, cluster_name, update_id, timeout_s, interval_s=15.0):
    eks = ctx.client("eks")
    update = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return update["status"]


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes asynchronously: its ENIs
# outlive its delete, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry DependencyViolation in the same
# window shared by all of one check's network deletes, then raise naming the ENIs still attached.
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
