"""concurrent-podidentity-association-update-serialization."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "concurrent-podidentity-association-update-serialization"
GROUP = "concurrency"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two simultaneous UpdatePodIdentityAssociation calls with different roleArns both succeed
    and the association ends on exactly one of the two roles: writes are serialized with no
    torn state."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    cluster_name = cluster["cluster_name"]

    role_initial = _create_pod_identity_role(ctx)
    role_b = _create_pod_identity_role(ctx)
    role_c = _create_pod_identity_role(ctx)

    namespace = "default"
    service_account = _k8s_name(ctx.unique_name("sim2real-sa-"))
    assoc = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace=namespace,
        serviceAccount=service_account,
        roleArn=role_initial,
    )["association"]
    association_id = assoc["associationId"]

    barrier = threading.Barrier(2)

    def _racer(role_arn):
        barrier.wait(timeout=10)
        return eks.update_pod_identity_association(
            clusterName=cluster_name, associationId=association_id, roleArn=role_arn
        )["association"]["roleArn"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_racer, role_b), pool.submit(_racer, role_c)]
        results = [f.result() for f in futures]

    for i, r in enumerate(results):
        assert r in (role_b, role_c), (
            f"racer {i} response roleArn {r!r} matches neither submitted racer value "
            f"({role_b!r}, {role_c!r})"
        )

    final = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert final["roleArn"] in (role_b, role_c), (
        f"final roleArn {final['roleArn']!r} is neither racer's value "
        f"({role_b!r}, {role_c!r}) -- torn/mixed state"
    )


# ===== helpers =====

_CLUSTER_CREATE_TIMEOUT_S = 1200.0
_CLUSTER_POLL_INTERVAL_S = 20.0


def _k8s_name(raw: str) -> str:
    return raw.lower().replace("_", "-")[:63].strip("-")


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

    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=azs[i]["ZoneName"]
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        ec2.create_tags(
            Resources=[sid], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-subnet-")}]
        )

    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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


def _create_pod_identity_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-podid-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


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
