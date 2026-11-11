"""delete-inuse-certificate-authority-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "delete-inuse-certificate-authority-rejected"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCertificateAuthority on the IN_USE signing CA is rejected with ResourceInUseException
    and leaves it intact and IN_USE, while a NOT_USED successor deletes cleanly: the rejection is
    state-specific."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    cluster_name = cluster["cluster_name"]

    cas = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(cas) == 1, f"expected exactly one CA on a freshly created cluster, found {len(cas)}"
    signer_id = cas[0]["id"]

    code, message = _error(
        lambda: eks.delete_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=signer_id
        )
    )
    assert code == "ResourceInUseException", (
        f"expected ResourceInUseException deleting the IN_USE signer {signer_id}, got {code!r}"
    )
    assert message == "Cannot delete the active certificate authority. Activate a different CA first.", message

    still_there = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=signer_id
    )["certificateAuthority"]
    assert still_there["signingStatus"] == "IN_USE", (
        f"rejected delete must leave the signer IN_USE, got {still_there['signingStatus']!r}"
    )

    # Positive control: a freshly appended successor (not the signer) can be deleted
    # once its own append-update has finished (a cluster only allows one update
    # in-flight at a time, so deleting immediately after create would itself race
    # with that in-progress update).
    successor_resp = eks.create_certificate_authority(clusterName=cluster_name)
    successor = successor_resp["certificateAuthority"]
    successor_id = successor["id"]
    assert successor["signingStatus"] == "NOT_USED", (
        f"a freshly appended successor CA must start NOT_USED, got {successor['signingStatus']!r}"
    )

    create_update_id = successor_resp["update"]["id"]
    _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=create_update_id)["update"]["status"],
        lambda s: s in ("Successful", "Failed", "Cancelled"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    create_status = eks.describe_update(name=cluster_name, updateId=create_update_id)["update"]["status"]
    assert create_status == "Successful", f"CA append update must succeed, got {create_status!r}"

    delete_resp = eks.delete_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=successor_id
    )
    update_id = delete_resp["update"]["id"]
    _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"],
        lambda s: s in ("Successful", "Failed", "Cancelled"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    delete_status = eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"]
    assert delete_status == "Successful", f"unprotected successor CA delete must succeed, got {delete_status!r}"

    # message varies: the text embeds a per-request Request ID and SDK attempt count
    final_code, _final_message = _error(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=successor_id
        )
    )
    assert final_code == "ResourceNotFoundException", (
        f"deleted CA {successor_id} must read back not-found, got {final_code!r}"
    )

    # The deleted id must also reject a mutation, not just a read.
    reactivate_code, reactivate_message = _error(
        lambda: eks.activate_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=successor_id
        )
    )
    assert reactivate_code == "ResourceNotFoundException", (
        f"activating the deleted CA {successor_id} must be not-found, got {reactivate_code!r}"
    )
    assert reactivate_message == (
        f"Certificate authority {successor_id} is not in the trusted list for cluster {cluster_name}"
    ), reactivate_message


# ===== helpers =====

_CLUSTER_CREATE_TIMEOUT_S = 1200.0
_CLUSTER_POLL_INTERVAL_S = 20.0


def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={last!r}")


def _create_cluster_with_retry(eks, cluster_name, role_arn, subnet_ids, timeout_s=120.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=cluster_name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}
            )
            return
        except Exception as exc:  # IAM role trust-policy propagation delay
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _delete_cluster_and_wait(eks, cluster_name, timeout_s=600.0, interval_s=15.0):
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
        time.sleep(interval_s)


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
    _create_cluster_with_retry(eks, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, cluster_name))

    status = _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"]["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_CREATE_TIMEOUT_S,
        interval_s=_CLUSTER_POLL_INTERVAL_S,
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
