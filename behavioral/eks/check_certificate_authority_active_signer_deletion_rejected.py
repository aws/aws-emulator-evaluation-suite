"""certificate-authority-active-signer-deletion-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-authority-active-signer-deletion-rejected"
GROUP = "state-machine"
SERVICES = ["eks"]

_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_ACTIVE_CA_DELETE_MSG = "Cannot delete the active certificate authority. Activate a different CA first."
_CA_NOT_FOUND_HEAD = "certificate authority not found (Service: EksCertificateAuthority, Status Code: 404, Request ID: "
_CA_NOT_FOUND_TAIL = ") (SDK Attempt Count: 1)"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCertificateAuthority on the IN_USE signer fails with ResourceInUseException and its exact
    message and the CA stays listed and IN_USE, while a never-activated successor deletes once
    distributed and then describes as ResourceNotFoundException.
    """
    eks = ctx.client("eks")
    cluster = _create_active_eks_cluster(ctx)

    cas = eks.list_certificate_authorities(clusterName=cluster)["certificateAuthorities"]
    assert len(cas) == 1
    ca0_id = cas[0]["id"]
    assert cas[0]["signingStatus"] == "IN_USE"

    code, message = _error(
        lambda: eks.delete_certificate_authority(clusterName=cluster, certificateAuthorityId=ca0_id)
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    assert message == _ACTIVE_CA_DELETE_MSG, f"expected {_ACTIVE_CA_DELETE_MSG!r}, got {message!r}"

    # effect absent: the active signer is still present, unchanged
    after = eks.describe_certificate_authority(clusterName=cluster, certificateAuthorityId=ca0_id)["certificateAuthority"]
    assert after["id"] == ca0_id
    assert after["signingStatus"] == "IN_USE"
    still_listed = {ca["id"] for ca in eks.list_certificate_authorities(clusterName=cluster)["certificateAuthorities"]}
    assert ca0_id in still_listed

    # positive control: a customer-appended, never-activated successor CA is deletable
    successor = eks.create_certificate_authority(clusterName=cluster)["certificateAuthority"]
    successor_id = successor["id"]
    assert successor["signingStatus"] == "NOT_USED"
    # Distribution can take most of the body budget: keep 900 s for the delete's update wait.
    _wait_ca_distribution_complete(ctx, eks, cluster, successor_id, timeout_s=2400.0, reserve_s=900.0)

    delete = eks.delete_certificate_authority(clusterName=cluster, certificateAuthorityId=successor_id)
    _wait_update_successful(ctx, eks, cluster, delete["update"]["id"])

    gone_code, gone_msg = _error(
        lambda: eks.describe_certificate_authority(clusterName=cluster, certificateAuthorityId=successor_id)
    )
    assert gone_code == "ResourceNotFoundException", f"expected successor CA gone, got {gone_code}"
    # The message embeds a backend request id the check never sees; its fixed text is asserted.
    assert gone_msg.startswith(_CA_NOT_FOUND_HEAD) and gone_msg.endswith(_CA_NOT_FOUND_TAIL), gone_msg


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _ec2_tags(name):
    return [{"Key": "Name", "Value": name}, {"Key": "sim2real-managed", "Value": "true"}]


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_eks_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.78.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags(ctx.unique_name("sim2real-eks-vpc-"))}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.78.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags(ctx.unique_name(f"sim2real-eks-sn{i}-"))}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return subnet_ids


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _reserved_s(ctx, cap_s, reserve_s):
    """cap_s less the time later waits need, but never under what a fast target needs; a wait the
    reserve shortens ends as not graded, like one the run budget ended."""
    left = ctx.time_left()
    if left is None or not reserve_s:
        return cap_s
    return min(cap_s, max(min(60.0, left - 5.0), left - reserve_s))


def _wait_cluster_status(ctx, eks, name, target, timeout_s=1200.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == target:
            return
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {target}")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {name} reaching {target}: the run budget ended first; not graded")
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s")


def _wait_cluster_gone(eks, name, timeout_s=1200):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"cluster {name} was not removed within {timeout_s}s")


def _create_active_eks_cluster(ctx):
    eks = ctx.client("eks")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _create_eks_vpc_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-clu-")
    # A just-created role is refused with InvalidParameterException until IAM propagates it.
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("creating the cluster while its new role propagates: the run budget ended first; not graded") from e
                raise
        time.sleep(2)

    def _cleanup():
        try:
            eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _wait_cluster_gone(eks, name)

    ctx.on_cleanup(_cleanup)
    _wait_cluster_status(ctx, eks, name, "ACTIVE")
    return name


def _wait_ca_distribution_complete(ctx, eks, cluster, ca_id, timeout_s=1500.0, reserve_s=0.0):
    cap_s = _budget_s(ctx, timeout_s)
    timeout_s = _reserved_s(ctx, cap_s, reserve_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ca = eks.describe_certificate_authority(clusterName=cluster, certificateAuthorityId=ca_id)["certificateAuthority"]
        if ca["distributionStatus"] == "COMPLETE":
            return ca
        if ca["distributionStatus"] == "FAILED":
            raise AssertionError(f"CA {ca_id} distribution FAILED")
        time.sleep(2)
    if _budget_spent(ctx) or timeout_s < cap_s:
        raise TimeoutError(f"CA {ca_id} distribution completing: the run budget ended first; not graded")
    raise AssertionError(f"CA {ca_id} distribution did not complete within {timeout_s}s")


def _wait_update_successful(ctx, eks, cluster, update_id, timeout_s=900.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        update = eks.describe_update(name=cluster, updateId=update_id)["update"]
        if update["status"] == "Successful":
            return update
        if update["status"] in ("Failed", "Cancelled"):
            raise AssertionError(f"update {update_id} ended in {update['status']}")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"update {update_id} completing: the run budget ended first; not graded")
    raise AssertionError(f"update {update_id} did not complete within {timeout_s}s")


# Network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind, so
# wait (bounded) for them to go, retry DependencyViolation in the same window, and raise naming the
# ENIs still attached. The window is shared by all of one check's network deletes.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
