"""duplicate-podidentity-association-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "duplicate-podidentity-association-rejected"
GROUP = "concurrency"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreatePodIdentityAssociation for the same (namespace, serviceAccount) is
    refused with ResourceInUseException and leaves the original roleArn untouched, while a
    different serviceAccount in the same namespace associates successfully."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    cluster_name = cluster["cluster_name"]

    role_a = _create_pod_identity_role(ctx)
    role_b = _create_pod_identity_role(ctx)
    namespace = "default"
    service_account = _k8s_name(ctx.unique_name("sim2real-sa-"))

    first = eks.create_pod_identity_association(
        clusterName=cluster_name, namespace=namespace, serviceAccount=service_account, roleArn=role_a
    )["association"]
    first_id = first["associationId"]

    code, msg = _error_code(
        lambda: eks.create_pod_identity_association(
            clusterName=cluster_name,
            namespace=namespace,
            serviceAccount=service_account,
            roleArn=role_b,
        )
    )
    assert code == "ResourceInUseException", (
        f"expected a duplicate (namespace, serviceAccount) association to be rejected with "
        f"ResourceInUseException, got {code!r}"
    )
    expected = f"The service account is already associated with a different IAM role: {role_a}"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    unchanged = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=first_id
    )["association"]
    assert unchanged["roleArn"] == role_a, (
        f"a rejected duplicate must not mutate the existing association's roleArn: "
        f"expected {role_a!r}, got {unchanged['roleArn']!r}"
    )

    other_service_account = _k8s_name(ctx.unique_name("sim2real-sa2-"))
    second = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace=namespace,
        serviceAccount=other_service_account,
        roleArn=role_b,
    )["association"]
    assert second["associationId"] != first_id, (
        f"a different serviceAccount must get a distinct associationId, got the same id {first_id!r}"
    )
    assert second["roleArn"] == role_b, (
        f"expected the positive-control association to bind roleArn {role_b!r}, got {second['roleArn']!r}"
    )

    # restore: once the association occupying (namespace, serviceAccount) is gone, the
    # identical pair that was rejected above must be accepted again -- proving the
    # rejection was specifically the uniqueness constraint, not a general fault.
    eks.delete_pod_identity_association(clusterName=cluster_name, associationId=first_id)
    gone_code, gone_msg = _error_code(
        lambda: eks.describe_pod_identity_association(clusterName=cluster_name, associationId=first_id)
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected the deleted association {first_id!r} to read back as ResourceNotFoundException, "
        f"got {gone_code!r}"
    )
    expected_gone = f"No service account role association found for ID: {first_id}"
    assert gone_msg == expected_gone, f"expected message {expected_gone!r}, got {gone_msg!r}"

    restored = eks.create_pod_identity_association(
        clusterName=cluster_name, namespace=namespace, serviceAccount=service_account, roleArn=role_b
    )["association"]
    described = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=restored["associationId"]
    )["association"]
    assert described["roleArn"] == role_b, (
        f"the identical (namespace, serviceAccount) pair must be creatable again once the original "
        f"association is deleted, and bind the new roleArn {role_b!r}, got {described['roleArn']!r}"
    )


# ===== helpers =====

_CLUSTER_CREATE_TIMEOUT_S = 1200.0
_CLUSTER_POLL_INTERVAL_S = 20.0


def _k8s_name(raw: str) -> str:
    return raw.lower().replace("_", "-")[:63].strip("-")


def _error_code(fn):
    """Call fn(); return the (Code, Message) of the error it raises, and raise on success."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
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

    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=azs[i]["ZoneName"]
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


# AWS-managed ENIs (endpoints, load balancers, functions) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
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
