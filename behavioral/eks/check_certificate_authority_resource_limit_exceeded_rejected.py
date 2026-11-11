"""certificate-authority-resource-limit-exceeded-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "certificate-authority-resource-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A cluster holds at most two certificate authorities: a third CreateCertificateAuthority is
    rejected with InvalidRequestException ("invalid given the state of the cluster"), and after the
    successor is deleted the identical create succeeds again."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    before = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(before) == 1, f"expected a single default (active) CA before rotation, got {len(before)}"
    outgoing_id = before[0]["id"]

    created = eks.create_certificate_authority(clusterName=cluster_name)
    successor_id = created["certificateAuthority"]["id"]
    terminal = _poll_update_terminal(ctx, cluster_name, created["update"]["id"])
    assert terminal == "Successful", f"successor CA append update ended in {terminal}, not Successful"

    mid = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(mid) == 2, f"expected 2 CAs (active + successor) present, got {len(mid)}"

    # break exactly one thing: try to append a third CA while the cluster already has its max of 2
    err = _error(lambda: eks.create_certificate_authority(clusterName=cluster_name))
    assert err == ("InvalidRequestException", "Cluster already has the maximum number of certificate authorities (2). Delete an existing CA before creating a new one."), f"expected InvalidRequestException for a third CA past the two-CA cap, got {err!r}"

    # effect absent: the rejected call must not have added a third CA
    after = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(after) == 2, f"a rejected CreateCertificateAuthority must not add a third CA, got {len(after)}"
    assert {c["id"] for c in after} == {c["id"] for c in mid}, f"CA id set changed after a rejected create: {after}"

    # restore: deleting the (unused) successor CA we legitimately created lifts the cap
    deleted = eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    delete_terminal = _poll_update_terminal(ctx, cluster_name, deleted["update"]["id"])
    assert delete_terminal == "Successful", f"successor CA delete update ended in {delete_terminal}, not Successful"
    final = _poll_ca_count(ctx, cluster_name, expected_count=1)
    assert final[0]["signingStatus"] == "IN_USE", f"expected the remaining CA to be IN_USE, got {final[0].get('signingStatus')!r}"

    # the identical create call, rejected above while at the cap, now succeeds with the cap lifted
    recreated = eks.create_certificate_authority(clusterName=cluster_name)
    recreated_id = recreated["certificateAuthority"]["id"]
    assert recreated_id not in (outgoing_id, successor_id), f"recreated CA id {recreated_id!r} collided with a prior CA id"
    recreate_terminal = _poll_update_terminal(ctx, cluster_name, recreated["update"]["id"])
    assert recreate_terminal == "Successful", f"the identical create call ended in {recreate_terminal!r} after the cap was lifted"

    after_restore = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    after_restore_ids = {c["id"] for c in after_restore}
    assert after_restore_ids == {outgoing_id, recreated_id}, (
        f"expected exactly the outgoing CA plus the newly recreated successor, got {after_restore_ids}"
    )


# ===== helpers =====
_EKS_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _tag_spec(ctx: Any, resource_type: str, name_prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-{name_prefix}-")}],
    }


def _create_cluster_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_EKS_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
    )
    return role_arn


def _create_cluster_subnets(ctx: Any) -> list:
    ec2 = ctx.client("ec2")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "zone-type", "Values": ["availability-zone"]},
                {"Name": "state", "Values": ["available"]},
            ]
        )["AvailabilityZones"]
    ][:2]
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", "subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_cluster_with_retry(eks: Any, name: str, role_arn: str, subnet_ids: list, timeout_s: float = 180.0) -> None:
    """Retries CreateCluster on InvalidParameterException, which EKS returns while the
    freshly-created IAM role is not yet assumable (trust-policy propagation delay)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "InvalidParameterException":
                raise
            time.sleep(2)
    raise AssertionError(f"CreateCluster kept failing with {last_code} after {timeout_s}s (IAM role propagation?)")


def _create_active_cluster(ctx: Any) -> str:
    """Creates a minimal EKS cluster (control plane only) and blocks until ACTIVE."""
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _create_cluster_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")
    _create_cluster_with_retry(eks, name, role_arn, subnet_ids)

    def _cleanup_cluster() -> None:
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
            except eks.exceptions.ResourceNotFoundException:
                return
            time.sleep(15.0)

    ctx.on_cleanup(_cleanup_cluster)

    deadline = time.monotonic() + 1200.0
    status = None
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == "ACTIVE":
            return name
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for ACTIVE")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within timeout (last status={status})")


def _poll_update_terminal(ctx: Any, cluster_name: str, update_id: str, timeout_s: float = 900.0) -> str:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"]
        if status in ("Successful", "Failed", "Cancelled"):
            return status
        time.sleep(2)
    raise AssertionError(f"update {update_id} did not reach terminal state within {timeout_s}s (last={status})")


def _poll_ca_count(ctx: Any, cluster_name: str, expected_count: int, timeout_s: float = 300.0) -> list:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    cas: list = []
    while time.monotonic() < deadline:
        cas = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
        if len(cas) == expected_count:
            return cas
        time.sleep(2)
    raise AssertionError(f"expected {expected_count} CAs, still have {len(cas)} after {timeout_s}s")


def _error(fn) -> Any:
    """Call fn() and return its error (Code, Message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel, so an accepted call fails as acceptance rather than as a code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


# EC2 network teardown: a cluster in this VPC deletes asynchronously and its ENIs keep DeleteSubnet /
# DeleteVpc failing with DependencyViolation for minutes, so wait for the ENIs, retry that code to one
# deadline shared by the check's network deletes, then raise naming the ENIs still attached.
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
