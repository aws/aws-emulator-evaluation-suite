"""certificate-authority-delete-in-use-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-authority-delete-in-use-blocked"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCertificateAuthority on the IN_USE signing CA is refused with ResourceInUseException and
    leaves it unchanged; once a successor CA is activated the identical delete succeeds, and a repeat
    delete on the dead id returns 404 rather than ResourceInUseException."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    cas = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    active = [c for c in cas if c["signingStatus"] == "IN_USE"]
    assert len(active) == 1, f"expected exactly one active CA, found {len(active)}"
    active_id = active[0]["id"]

    # break exactly one thing: try to delete the CA that is actively signing
    code = _error_code(
        lambda: eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=active_id)
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException deleting the in-use CA, got {code!r}"

    # effect absent: the active CA must still be present and still IN_USE
    still_there = eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=active_id)
    still_status = still_there["certificateAuthority"]["signingStatus"]
    assert still_status == "IN_USE", f"expected {active_id} to remain IN_USE after the rejected delete, got {still_status!r}"

    # positive control: the CA write path still works while the original CA is IN_USE
    created = eks.create_certificate_authority(clusterName=cluster_name)
    successor_id = created["certificateAuthority"]["id"]
    created_status = created["certificateAuthority"]["signingStatus"]
    assert created_status == "NOT_USED", f"expected a freshly created successor to start NOT_USED, got {created_status!r}"
    create_terminal = _poll_update_terminal(ctx, cluster_name, created["update"]["id"])
    assert create_terminal == "Successful", f"expected successor CA creation to reach Successful, got {create_terminal!r}"

    # restore: activate the successor. This retires active_id out of IN_USE -- the specific
    # state that made the earlier delete illegal. A freshly-created successor's
    # distributionStatus can stay IN_PROGRESS on its own (waiting for COMPLETE first can
    # deadlock); ActivateCertificateAuthority itself
    # transiently answers InvalidRequestException ("distributionStatus must be COMPLETE") until
    # distribution catches up, and separately ResourceInUseException ("cluster ... currently has
    # update ... in progress") while the cluster is still settling the successor's own create
    # update even after DescribeUpdate already reports it Successful. Call activate directly and
    # retry both transient rejections bounded, keeping 600 s for the activation and
    # delete update waits.
    activated = _retry_ca_call(
        ctx,
        lambda: eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id),
        timeout_s=2400.0,
        reserve_s=600.0,
    )
    activate_terminal = _poll_update_terminal(ctx, cluster_name, activated["update"]["id"])
    assert activate_terminal == "Successful", f"expected successor activation to reach Successful, got {activate_terminal!r}"

    retired = eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=active_id)
    retired_status = retired["certificateAuthority"]["signingStatus"]
    assert retired_status == "NOT_USED", (
        f"expected {active_id} to retire to NOT_USED once {successor_id} activated, got {retired_status!r}"
    )

    now_active = eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    now_active_status = now_active["certificateAuthority"]["signingStatus"]
    assert now_active_status == "IN_USE", (
        f"expected successor {successor_id} to become IN_USE after activation, got {now_active_status!r}"
    )

    # the identical call now succeeds: the CA that was rejected for being IN_USE can be
    # deleted once it is no longer the one signing. It can transiently hit the same
    # cluster-busy ResourceInUseException the activation retry above tolerates -- retired_status
    # was independently confirmed NOT_USED above, so this is the cluster settling the activation
    # update, not a real still-in-use rejection.
    deleted = _retry_ca_call(
        ctx,
        lambda: eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=active_id),
        timeout_s=300.0,
    )
    delete_terminal = _poll_update_terminal(ctx, cluster_name, deleted["update"]["id"])
    assert delete_terminal == "Successful", f"expected the now-retired CA's delete to reach Successful, got {delete_terminal!r}"

    # deletes prove gone and unusable: an independent read 404s, and a further mutation on
    # the same dead id 404s too
    gone_code = _error_code(
        lambda: eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=active_id)
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected deleted CA {active_id} to read as ResourceNotFoundException, got {gone_code!r}"
    )

    dead_mutation_code = _error_code(
        lambda: eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=active_id)
    )
    assert dead_mutation_code == "ResourceNotFoundException", (
        f"expected a second delete of the already-deleted {active_id} to 404, got {dead_mutation_code!r}"
    )


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


def _create_active_cluster(ctx: Any) -> str:
    """Creates a minimal EKS cluster (control plane only) and blocks until ACTIVE."""
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _create_cluster_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")

    # the freshly-created IAM role's trust policy is eventually consistent; EKS may not yet be
    # able to assume it immediately after creation. Retry the specific transient rejection
    # (confirmed against real AWS) with a bounded deadline instead of a blind sleep.
    create_deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() >= create_deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("creating the cluster while its new role propagates: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)

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
            time.sleep(2)
        raise AssertionError(f"cluster {name} still exists 900 s after DeleteCluster")

    ctx.on_cleanup(_cleanup_cluster)

    deadline = time.monotonic() + _budget_s(ctx, 1200.0)
    status = None
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == "ACTIVE":
            return name
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for ACTIVE")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {name} reaching ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"cluster {name} did not reach ACTIVE within timeout (last status={status})")


def _budget_s(ctx: Any, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx: Any) -> bool:
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


def _poll_update_terminal(ctx: Any, cluster_name: str, update_id: str, timeout_s: float = 900.0) -> str:
    eks = ctx.client("eks")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"]
        if status in ("Successful", "Failed", "Cancelled"):
            return status
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"update {update_id} reaching a terminal state: the run budget ended first; not graded")
    raise AssertionError(f"update {update_id} did not reach terminal state within {timeout_s}s (last={status})")


_TRANSIENT_CA_CODES = frozenset({"InvalidRequestException", "ResourceInUseException"})


def _retry_ca_call(ctx: Any, fn, *, timeout_s: float, reserve_s: float = 0.0) -> dict:
    """A CA-rotation call (activate or delete) can transiently answer
    InvalidRequestException ("distributionStatus must be COMPLETE") until a just-created
    successor's distribution catches up -- that distribution does not complete on its own, it
    sits at IN_PROGRESS indefinitely absent an activation attempt -- and separately
    ResourceInUseException while the cluster is still settling a prior update even after
    DescribeUpdate already reports that update Successful. Retry the call itself, bounded,
    rather than polling for either signal first."""
    cap_s = _budget_s(ctx, timeout_s)
    window_s = _reserved_s(ctx, cap_s, reserve_s)
    deadline = time.monotonic() + window_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _TRANSIENT_CA_CODES:
                raise
            last_err = exc
            time.sleep(2)
    if _budget_spent(ctx) or window_s < cap_s:
        raise TimeoutError("a CA rotation call accepted: the run budget ended first; not graded") from last_err
    raise last_err


def _error_code(fn) -> Any:
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaked the
# VPC while the check PASSED. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes.
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
