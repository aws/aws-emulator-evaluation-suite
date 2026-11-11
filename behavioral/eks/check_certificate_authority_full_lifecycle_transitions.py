"""certificate-authority-full-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "certificate-authority-full-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A successor CA starts NOT_USED; once its distribution is COMPLETE, activation makes it IN_USE
    and retires the original to NOT_USED, and the retired CA then deletes and describes as
    ResourceNotFoundException while the successor stays listed."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    cluster_name = cluster["cluster_name"]

    initial = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(initial) == 1, f"expected exactly one CA on a freshly created cluster, got {initial}"
    original_id = initial[0]["id"]
    assert initial[0]["signingStatus"] == "IN_USE", f"initial CA should be IN_USE, got {initial[0]}"

    created = eks.create_certificate_authority(clusterName=cluster_name)
    successor_id = created["certificateAuthority"]["id"]
    assert created["certificateAuthority"]["signingStatus"] == "NOT_USED", created["certificateAuthority"]
    assert successor_id != original_id, "successor CA must be a distinct id from the original"

    # Real AWS rejects ActivateCertificateAuthority with InvalidRequestException
    # ("cannot activate CA: distributionStatus must be COMPLETE") while a freshly
    # appended successor is still distributing, so distribution completion is a real
    # precondition to wait out, not something activation itself drives.
    _poll_until(
        ctx,
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=successor_id
        )["certificateAuthority"]["distributionStatus"],
        lambda s: s == "COMPLETE",
        timeout_s=1800.0,
    )

    activation = eks.activate_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=successor_id
    )
    activate_update_id = activation["update"]["id"]
    activate_status = _poll_until(
        ctx,
        lambda: eks.describe_update(name=cluster_name, updateId=activate_update_id)["update"]["status"],
        lambda s: s in ("Successful", "Failed", "Cancelled"),
        timeout_s=900.0,
    )
    assert activate_status == "Successful", f"activation update {activate_update_id} ended in {activate_status}"

    successor_final = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=successor_id
    )["certificateAuthority"]
    assert successor_final["signingStatus"] == "IN_USE", successor_final
    assert successor_final["distributionStatus"] == "COMPLETE", successor_final

    original_retired = _poll_until(
        ctx,
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=original_id
        )["certificateAuthority"]["signingStatus"],
        lambda s: s == "NOT_USED",
        timeout_s=300.0,
    )
    assert original_retired == "NOT_USED", f"outgoing CA should retire to NOT_USED, got {original_retired}"

    delete_resp = eks.delete_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=original_id
    )
    delete_update_id = delete_resp["update"]["id"]
    delete_status = _poll_until(
        ctx,
        lambda: eks.describe_update(name=cluster_name, updateId=delete_update_id)["update"]["status"],
        lambda s: s in ("Successful", "Failed", "Cancelled"),
        timeout_s=600.0,
    )
    assert delete_status == "Successful", f"delete update {delete_update_id} ended in {delete_status}"

    code, message = _error(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=original_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    # The message embeds a backend request id the check never sees; its fixed text is asserted.
    assert message.startswith(
        "certificate authority not found (Service: EksCertificateAuthority, Status Code: 404, Request ID: "
    ) and message.endswith(") (SDK Attempt Count: 1)"), message

    remaining_ids = {
        ca["id"] for ca in eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    }
    assert original_id not in remaining_ids, f"deleted CA {original_id} still listed: {remaining_ids}"
    assert successor_id in remaining_ids, f"active successor {successor_id} missing from list: {remaining_ids}"


# ===== helpers =====

_CLUSTER_CREATE_TIMEOUT_S = 1200.0


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
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


def _poll_until(ctx, probe, predicate, timeout_s=300.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"waiting on {last!r}: the run budget ended first; not graded")
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={last!r}")


def _create_cluster_with_retry(ctx, eks, cluster_name, role_arn, subnet_ids, tags=None):
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    last_exc = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags=tags or {},
            )
            return
        except Exception as exc:  # IAM role trust-policy propagation delay
            last_exc = exc
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("creating the cluster while its new role propagates: the run budget ended first; not graded") from last_exc
    raise last_exc


def _delete_cluster_and_wait(eks, cluster_name, timeout_s=600.0):
    try:
        eks.delete_cluster(name=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=cluster_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_name} still exists {timeout_s}s after DeleteCluster")


def _create_active_cluster(ctx):
    """Provision a minimal VPC + IAM role + EKS cluster and wait for ACTIVE."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")

    vpc_name = ctx.unique_name("sim2real-eks-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        subnet_name = ctx.unique_name(f"sim2real-eks-subnet{i}-")
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=azs[i]["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))

    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
        )
    )

    cluster_name = ctx.unique_name("sim2real-eks-")
    _create_cluster_with_retry(ctx, eks, cluster_name, role_arn, subnet_ids, tags={"Name": cluster_name})
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, cluster_name))

    status = _poll_until(
        ctx,
        lambda: eks.describe_cluster(name=cluster_name)["cluster"]["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_CREATE_TIMEOUT_S,
    )
    if status != "ACTIVE":
        raise AssertionError(f"cluster {cluster_name} did not reach ACTIVE, got {status}")

    return {"cluster_name": cluster_name, "role_arn": role_arn, "subnet_ids": subnet_ids, "vpc_id": vpc_id}


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
