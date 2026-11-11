"""activate-certificate-authority-before-distribution-complete-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activate-certificate-authority-before-distribution-complete-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Activating a just-appended successor CA while its append update is InProgress fails with
    ResourceInUseException naming that update and leaves it NOT_USED with no activatedAt; once settled it
    deletes, then Describe and Activate fail with ResourceNotFoundException.
    """
    eks = ctx.client("eks")
    subnet_ids = _create_own_subnets(ctx)
    role_arn = _create_role(ctx, "eks.amazonaws.com", ["AmazonEKSClusterPolicy"])

    cluster_name = ctx.unique_name("sim2real-eks-caact-")
    _create_cluster_with_retry(eks, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, eks, cluster_name))
    _wait_cluster_status(ctx, eks, cluster_name, "ACTIVE", timeout_s=1500)

    # The check holds its own in-progress window: the append update it starts here.
    # The append response's own update status is the documented resting state of a
    # freshly started update.
    created = eks.create_certificate_authority(clusterName=cluster_name)
    successor_id = created["certificateAuthority"]["id"]
    append_update_id = created["update"]["id"]
    assert created["certificateAuthority"]["signingStatus"] == "NOT_USED"
    assert created["update"]["status"] == "InProgress", f"append update started as {created['update']['status']!r}"

    # Negative: activating while the append update is in flight is rejected --
    # ResourceInUseException naming the append update that holds the cluster.
    code, message = _error(
        lambda: eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code!r}"
    assert message == (
        f"Cannot CertificateAuthorityUpdate because cluster {cluster_name} "
        f"currently has update {append_update_id} in progress"
    ), f"unexpected message: {message!r}"

    # Effect absent: the successor is untouched -- still NOT_USED, not activated.
    unchanged = eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)[
        "certificateAuthority"
    ]
    assert unchanged["signingStatus"] == "NOT_USED", "successor's signing status changed despite the rejected activation"
    assert "activatedAt" not in unchanged, "successor recorded an activation timestamp despite the rejected activation"

    # Positive control: the successor CA record itself is fully functional -- once its
    # own append update has settled, it can be deleted normally (the rejection above is
    # about activation timing, not a frozen CA).
    append_status = _wait_update_terminal(ctx, eks, cluster_name, append_update_id, timeout_s=600)
    assert append_status == "Successful", f"successor CA append update ended in {append_status!r}, not Successful"
    delete_resp = eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    delete_status = _wait_update_terminal(ctx, eks, cluster_name, delete_resp["update"]["id"], timeout_s=600)
    assert delete_status == "Successful", f"delete of successor CA {successor_id} ended in {delete_status!r}, not Successful"
    _wait_ca_gone(eks, cluster_name, successor_id, timeout_s=900)

    remaining = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert successor_id not in {c["id"] for c in remaining}

    # Deletes prove gone and unusable: an independent read of the dead id fails with the
    # specific not-found code, and so does a further mutation attempted against it.
    describe_code, _describe_message = _error(
        lambda: eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    )
    assert describe_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {describe_code!r}"
    # message varies: it embeds the per-request Request ID

    activate_code, activate_message = _error(
        lambda: eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    )
    assert activate_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {activate_code!r}"
    assert activate_message == (
        f"Certificate authority {successor_id} is not in the trusted list for cluster {cluster_name}"
    ), f"unexpected message: {activate_message!r}"


def _error(fn):
    """Run fn, which must fail; return the (code, message) AWS sent."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("call succeeded but was expected to fail")


def _create_own_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-eks-caact-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.62.0.0/16",
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
        subnet_name = ctx.unique_name("sim2real-eks-caact-subnet-")
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.62.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe_delete_subnet(ec2, sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _safe_delete_subnet(ec2, subnet_id: str) -> None:
    try:
        _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _safe_delete_vpc(ec2, vpc_id: str) -> None:
    try:
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


def _create_role(ctx, service_principal: str, managed_policy_names: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name, managed_policy_names))
    for policy_name in managed_policy_names:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
    return role_arn


def _safe_delete_role(ctx, role_name: str, managed_policy_names: list[str]) -> None:
    iam = ctx.client("iam")
    for policy_name in managed_policy_names:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_cluster_with_retry(eks, name: str, role_arn: str, subnet_ids: list[str], timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real-managed": "true"},
            )
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ClientException":
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"CreateCluster kept failing with {last_code} after {timeout_s}s (IAM role propagation?)")


def _wait_cluster_status(ctx, eks, name: str, want: str, timeout_s: float, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last == want:
            return
        if last == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {want} within {timeout_s}s (last={last})")


def _wait_cluster_gone(ctx, eks, name: str, timeout_s: float, interval_s: float = 15.0) -> None:
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


def _safe_delete_cluster(ctx, eks, name: str) -> None:
    try:
        eks.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    _wait_cluster_gone(ctx, eks, name, timeout_s=900, interval_s=2.0)


def _wait_update_terminal(ctx, eks, cluster_name: str, update_id: str, timeout_s: float, interval_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"]
        if last in ("Successful", "Failed", "Cancelled"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} on {cluster_name} did not reach a terminal status within {timeout_s}s (last={last})")


def _wait_ca_gone(eks, cluster_name: str, ca_id: str, timeout_s: float, interval_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"certificate authority {ca_id} was not deleted within {timeout_s}s")


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
