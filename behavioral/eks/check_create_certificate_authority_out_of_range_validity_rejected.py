"""create-certificate-authority-out-of-range-validity-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-certificate-authority-out-of-range-validity-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCertificateAuthority has no validity input, so this exercises its real constraint:
    a second call while the first successor's cluster update is in flight is rejected with
    ResourceInUseException and leaves the CA set unchanged, after the first succeeded."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    initial = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(initial) == 1, f"expected exactly one CA on a freshly-created cluster, got {initial}"

    # positive control: appending a successor CA succeeds and starts an async cluster update.
    appended = eks.create_certificate_authority(clusterName=cluster_name)
    successor = appended["certificateAuthority"]
    in_flight_update_id = appended["update"]["id"]
    successor_id = successor["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_ca(eks, cluster_name, successor_id))
    assert successor["signingStatus"] == "NOT_USED", (
        f"expected a freshly appended successor CA to start NOT_USED, got {successor['signingStatus']}"
    )

    at_limit = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(at_limit) == 2, f"expected exactly two CAs after appending the successor, got {at_limit}"

    # break exactly one thing: request a second CreateCertificateAuthority while the first
    # successor's cluster update is still in flight.
    code, message = _error(lambda: eks.create_certificate_authority(clusterName=cluster_name))
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    expected = (
        f"Cannot CertificateAuthorityUpdate because cluster {cluster_name} "
        f"currently has update {in_flight_update_id} in progress"
    )
    assert message == expected, f"unexpected message: {message!r}, expected {expected!r}"

    # effect absent: the cluster still holds exactly the same two CAs, no third was created.
    after = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    after_ids = sorted(ca["id"] for ca in after)
    assert after_ids == sorted(ca["id"] for ca in at_limit), (
        f"rejected create must not add a third CA: before={at_limit}, after={after}"
    )
    assert len(after) == 2, f"expected the CA count to stay at 2 after the rejected create, got {after}"


# ===== helpers =====
def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _best_effort_delete_ca(eks, cluster_name, ca_id):
    """A refusal while the CA's own update is in progress is left to DeleteCluster, which
    removes the CA with the cluster and raises if that fails."""
    try:
        eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ResourceInUseException" and "in progress" in err.get("Message", ""):
            return
        if err["Code"] != "ResourceNotFoundException":
            raise


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))[
        "Role"
    ]["Arn"]
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
    vpc_id = ec2.create_vpc(CidrBlock="10.50.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.50.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return subnet_ids


def _delete_cluster_when_idle(eks, name, timeout_s=1200):
    """Teardown: a successor CA leaves a cluster update in flight, and DeleteCluster refuses
    a cluster with an update in progress, so retry ResourceInUseException (bounded)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _create_vpc_and_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cl-")

    deadline = time.monotonic() + 180
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)  # IAM role propagation delay
                continue
            raise

    def _cleanup_cluster():
        # One 1200 s deadline for the in-flight CA update to settle and the cluster to delete.
        deadline = time.monotonic() + 1200
        _delete_cluster_when_idle(eks, name, timeout_s=1200)
        attempts = min(360, max(1, int((deadline - time.monotonic()) / 2)))
        waiter = eks.get_waiter("cluster_deleted")
        waiter.wait(name=name, WaiterConfig={"Delay": 2, "MaxAttempts": attempts})

    ctx.on_cleanup(_cleanup_cluster)
    waiter = eks.get_waiter("cluster_active")
    waiter.wait(name=name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
    return name


# EC2 network teardown: a cluster in this VPC deletes asynchronously and its ENIs keep DeleteSubnet /
# DeleteVpc failing with DependencyViolation for minutes, so wait for the ENIs, retry that code to one
# deadline shared by the check's network deletes, then raise naming the ENIs still attached.
_NET_TEARDOWN_S = 540.0
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
