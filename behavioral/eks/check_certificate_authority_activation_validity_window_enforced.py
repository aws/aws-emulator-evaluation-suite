"""certificate-authority-activation-validity-window-enforced."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-authority-activation-validity-window-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["eks"]

_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_CLOCK_SKEW = timedelta(seconds=2)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCertificateAuthority reports a validity window for the original signer and an activated
    successor CA; for each, now lies in [notBefore, notAfter), and the successor's activatedAt
    lies inside its own window.
    """
    eks = ctx.client("eks")
    cluster = _create_active_eks_cluster(ctx)

    cas = eks.list_certificate_authorities(clusterName=cluster)["certificateAuthorities"]
    ca0_id = cas[0]["id"]
    ca0 = eks.describe_certificate_authority(clusterName=cluster, certificateAuthorityId=ca0_id)["certificateAuthority"]
    _assert_validity_window_currently_valid(ca0)

    created = eks.create_certificate_authority(clusterName=cluster)["certificateAuthority"]
    ca1_id = created["id"]
    _wait_ca_distribution_complete(ctx, eks, cluster, ca1_id)

    activate = eks.activate_certificate_authority(clusterName=cluster, certificateAuthorityId=ca1_id)
    _wait_update_successful(ctx, eks, cluster, activate["update"]["id"])
    ca1 = _poll_ca_signing_status(ctx, eks, cluster, ca1_id, "IN_USE")

    _assert_validity_window_currently_valid(ca1)
    assert ca1["activatedAt"] >= ca1["validity"]["notBefore"], (
        f"CA {ca1['id']} activatedAt ({ca1['activatedAt']}) precedes its own validity "
        f"window start ({ca1['validity']['notBefore']})"
    )
    assert ca1["activatedAt"] < ca1["validity"]["notAfter"], (
        f"CA {ca1['id']} activatedAt ({ca1['activatedAt']}) is not before its own validity "
        f"window end ({ca1['validity']['notAfter']})"
    )


def _assert_validity_window_currently_valid(ca):
    validity = ca["validity"]
    not_before = validity["notBefore"]
    not_after = validity["notAfter"]
    assert not_before < not_after, f"CA {ca['id']} has an inverted validity window: {validity}"
    now = datetime.now(timezone.utc)
    # The local clock and the service clock may differ by a moment; allow that much on notBefore.
    assert not_before <= now + _CLOCK_SKEW and now < not_after, (
        f"CA {ca['id']} is currently signing but 'now' ({now}) falls outside its "
        f"reported validity window {validity}"
    )



def _ec2_tags(name):
    return [{"Key": "Name", "Value": name}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_eks_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.80.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags(ctx.unique_name("sim2real-eks-vpc-"))}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.80.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags(ctx.unique_name(f"sim2real-eks-sn{i}-"))}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return subnet_ids


def _wait_cluster_status(ctx, eks, name, target, timeout_s=1200, interval_s=2):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == target:
            return
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {target}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {name} reaching {target}: the run budget ended first; not graded")
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s")


def _wait_cluster_gone(eks, name, timeout_s=1200, interval_s=3):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not removed within {timeout_s}s")


def _create_active_eks_cluster(ctx):
    eks = ctx.client("eks")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _create_eks_vpc_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-clu-")
    deadline = time.monotonic() + _budget_s(ctx, 80.0)
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterException" and time.monotonic() < deadline:
                # the role/policy attachment above has not yet propagated to EKS
                time.sleep(2)
                continue
            if code == "InvalidParameterException" and _budget_spent(ctx):
                raise TimeoutError(f"CreateCluster {name} past IAM propagation: the run budget ended first; not graded") from exc
            raise

    def _cleanup():
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _wait_cluster_gone(eks, name)

    ctx.on_cleanup(_cleanup)
    _wait_cluster_status(ctx, eks, name, "ACTIVE")
    return name


def _wait_ca_distribution_complete(ctx, eks, cluster, ca_id, timeout_s=1800, interval_s=2):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        ca = eks.describe_certificate_authority(clusterName=cluster, certificateAuthorityId=ca_id)["certificateAuthority"]
        last_status = ca["distributionStatus"]
        if last_status == "COMPLETE":
            return ca
        if last_status == "FAILED":
            raise AssertionError(f"CA {ca_id} distribution FAILED")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"CA {ca_id} distribution completing: the run budget ended first; not graded")
    raise AssertionError(
        f"CA {ca_id} distribution did not complete within {timeout_s}s, last saw distributionStatus={last_status}"
    )


def _wait_update_successful(ctx, eks, cluster, update_id, timeout_s=900, interval_s=2):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        update = eks.describe_update(name=cluster, updateId=update_id)["update"]
        if update["status"] == "Successful":
            return update
        if update["status"] in ("Failed", "Cancelled"):
            raise AssertionError(f"update {update_id} ended in {update['status']}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"update {update_id} completing: the run budget ended first; not graded")
    raise AssertionError(f"update {update_id} did not complete within {timeout_s}s")


def _poll_ca_signing_status(ctx, eks, cluster, ca_id, target, timeout_s=300, interval_s=2):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    ca = None
    while time.monotonic() < deadline:
        ca = eks.describe_certificate_authority(clusterName=cluster, certificateAuthorityId=ca_id)["certificateAuthority"]
        if ca["signingStatus"] == target:
            return ca
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"CA {ca_id} signingStatus reaching {target}: the run budget ended first; not graded")
    raise AssertionError(f"CA {ca_id} signingStatus never reached {target}, last saw {ca}")


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
