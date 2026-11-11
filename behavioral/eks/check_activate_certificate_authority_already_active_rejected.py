"""activate-certificate-authority-already-active-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "activate-certificate-authority-already-active-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ActivateCertificateAuthority on the CA that is already the cluster's active signer
    (signingStatus IN_USE) is an invalid state transition and must be rejected with
    InvalidRequestException, not silently accepted as a no-op that spins up a new update."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    cas = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    active = [c for c in cas if c["signingStatus"] == "IN_USE"]
    assert len(active) == 1
    active_id = active[0]["id"]

    updates_before = set(eks.list_updates(name=cluster_name)["updateIds"])

    # break exactly one thing: activate a CA that is already the active signer
    err = _expect_error(
        lambda: eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=active_id)
    )
    assert err == (
        "InvalidRequestException",
        f"Certificate authority {active_id} is already active for cluster {cluster_name}",
    ), f"expected the already-active refusal, got {err!r}"

    # effect absent: no new asynchronous update was kicked off, and the CA is unchanged
    updates_after = set(eks.list_updates(name=cluster_name)["updateIds"])
    assert updates_after == updates_before, "a rejected Activate call must not create a new update"
    still = eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=active_id)
    assert still["certificateAuthority"]["signingStatus"] == "IN_USE"

    # positive control: the CA write path itself still works (appending a successor succeeds)
    created = eks.create_certificate_authority(clusterName=cluster_name)
    terminal = _poll_update_terminal(ctx, cluster_name, created["update"]["id"])
    assert terminal == "Successful"


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


def _create_cluster_with_role_propagation_retry(
    eks: Any, name: str, role_arn: str, subnet_ids: list, timeout_s: float = 90.0
) -> None:
    """create_cluster can 400 for a few seconds after CreateRole/AttachRolePolicy while the
    new role has not yet propagated to be assumable by eks.amazonaws.com; retry within a bound
    instead of guessing a fixed delay."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            return
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] not in ("InvalidParameterException", "ClientException"):
                raise
            time.sleep(2)
    raise AssertionError(f"create_cluster never succeeded (IAM role propagation?): {last_err}")


def _create_active_cluster(ctx: Any) -> str:
    """Creates a minimal EKS cluster (control plane only) and blocks until ACTIVE."""
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _create_cluster_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")
    _create_cluster_with_role_propagation_retry(eks, name, role_arn, subnet_ids)

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


def _expect_error(fn) -> Any:
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises, because
    an over-permissive target accepting what real AWS refuses must not be mistaken for a
    code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
