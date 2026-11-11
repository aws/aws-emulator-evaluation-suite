"""activate-certificate-authority-wrong-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags


CHECK = "activate-certificate-authority-wrong-state-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Activating a just-appended successor CA is rejected with ResourceInUseException while its
    append update is in flight (one update per cluster) and leaves it NOT_USED; once settled, the
    same CA deletes normally and then 404s on describe and activate."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    created = eks.create_certificate_authority(clusterName=cluster_name)
    ca_id = created["certificateAuthority"]["id"]
    append_update_id = created["update"]["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_ca(eks, cluster_name, ca_id))

    # Appending the successor CA starts an asynchronous cluster update.
    code = _expect_error(
        lambda: eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
    )
    assert code == (
        "ResourceInUseException",
        f"Cannot CertificateAuthorityUpdate because cluster {cluster_name} currently has update "
        f"{append_update_id} in progress",
    ), f"expected ResourceInUseException, got {code}"

    described = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=ca_id
    )["certificateAuthority"]
    assert described["signingStatus"] == "NOT_USED", (
        f"rejected activation must not change signingStatus, got {described['signingStatus']}"
    )

    # Positive control: the same CA is not broken -- once its update settles it deletes normally.
    # Full CA distribution can take far longer than any test window, so Activate is not retried.
    _wait_update_terminal(ctx, eks, cluster_name, append_update_id, timeout_s=600)
    delete_resp = eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
    _wait_update_terminal(ctx, eks, cluster_name, delete_resp["update"]["id"], timeout_s=600)

    remaining = {
        c["id"] for c in eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    }
    assert ca_id not in remaining, "deleted successor CA is still listed"

    describe_code = _expect_error(
        lambda: eks.describe_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
    )
    # message varies: the DescribeCertificateAuthority not-found text embeds the request id.
    assert describe_code[0] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {describe_code}"

    activate_code = _expect_error(
        lambda: eks.activate_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
    )
    assert activate_code == (
        "ResourceNotFoundException",
        f"Certificate authority {ca_id} is not in the trusted list for cluster {cluster_name}",
    ), f"expected ResourceNotFoundException, got {activate_code}"


def _expect_error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete_ca(eks, cluster_name, ca_id):
    try:
        eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_update_terminal(ctx, eks, cluster_name, update_id, timeout_s=600.0, interval_s=2.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"]
        if last in ("Successful", "Failed", "Cancelled"):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"update {update_id} on {cluster_name} reaching a terminal status: the run budget ended first; not graded")
    raise AssertionError(f"update {update_id} on {cluster_name} did not reach a terminal status within {timeout_s}s (last={last})")


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [
            {"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-{resource_type}-")},
            {"Key": "sim2real-managed", "Value": "true"},
        ],
    }


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    )

    def _cleanup():
        iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
        )
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.45.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.45.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _del_subnet(sid=subnet_id):
            for _ in range(60):
                try:
                    _delete_net(ec2, "delete_subnet", SubnetId=sid)
                    return
                except ClientError as exc:
                    if exc.response["Error"]["Code"] == "DependencyViolation":
                        time.sleep(2)
                        continue
                    raise

        ctx.on_cleanup(_del_subnet)
    return subnet_ids


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _create_vpc_and_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cl-")

    deadline = time.monotonic() + _budget_s(ctx, 180)
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real-managed": "true"},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)  # IAM role propagation delay
                continue
            if exc.response["Error"]["Code"] == "InvalidParameterException" and _budget_spent(ctx):
                raise TimeoutError(f"CreateCluster {name} past IAM role propagation: the run budget ended first; not graded") from exc
            raise

    def _cleanup_cluster():
        eks.delete_cluster(name=name)
        waiter = eks.get_waiter("cluster_deleted")
        waiter.wait(name=name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})

    ctx.on_cleanup(_cleanup_cluster)
    waiter = eks.get_waiter("cluster_active")
    attempts = max(1, int(_budget_s(ctx, 1800) / 2))
    try:
        waiter.wait(name=name, WaiterConfig={"Delay": 2, "MaxAttempts": attempts})
    except WaiterError:
        if _budget_spent(ctx):
            raise TimeoutError(f"cluster {name} ACTIVE: the run budget ended first; not graded") from None
        raise
    return name


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
