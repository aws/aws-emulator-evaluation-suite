"""create-pod-identity-association-conflicting-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pod-identity-association-conflicting-role-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePodIdentityAssociation for a namespace/serviceAccount already bound to another role is
    rejected with ResourceInUseException and the existing association keeps its role, while the
    conflicting role binds fine to a different service account."""
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _create_vpc_and_subnets(ctx)
    cluster_name, _cluster = _create_active_cluster(ctx, role_arn, subnet_ids)

    role_a = _create_pod_identity_role(ctx)
    role_b = _create_pod_identity_role(ctx)
    namespace = "default"
    service_account = ctx.unique_name("sim2real-sa-").replace("_", "-")

    first = eks.create_pod_identity_association(
        clusterName=cluster_name, namespace=namespace, serviceAccount=service_account, roleArn=role_a
    )
    assoc_id = first["association"]["associationId"]
    ctx.on_cleanup(lambda: eks.delete_pod_identity_association(clusterName=cluster_name, associationId=assoc_id))

    code, message = _error(
        lambda: eks.create_pod_identity_association(
            clusterName=cluster_name, namespace=namespace, serviceAccount=service_account, roleArn=role_b
        )
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    assert message == f"The service account is already associated with a different IAM role: {role_a}", message

    # effect absent: the original association still points at role_a, unchanged
    described = eks.describe_pod_identity_association(clusterName=cluster_name, associationId=assoc_id)["association"]
    assert described["roleArn"] == role_a
    matches = [
        a
        for a in eks.list_pod_identity_associations(clusterName=cluster_name, namespace=namespace, serviceAccount=service_account)[
            "associations"
        ]
    ]
    assert len(matches) == 1

    # positive control: role_b works fine for a different service account
    other_service_account = ctx.unique_name("sim2real-sa2-").replace("_", "-")
    second = eks.create_pod_identity_association(
        clusterName=cluster_name, namespace=namespace, serviceAccount=other_service_account, roleArn=role_b
    )
    second_id = second["association"]["associationId"]
    ctx.on_cleanup(lambda: eks.delete_pod_identity_association(clusterName=cluster_name, associationId=second_id))

    # terminal assertion is an independent read at the destination, not the create call's own response
    second_described = eks.describe_pod_identity_association(clusterName=cluster_name, associationId=second_id)[
        "association"
    ]
    assert second_described["roleArn"] == role_b, (
        f"expected the positive-control association to carry role_b, got {second_described['roleArn']}"
    )


# ===== helpers =====
_EKS_CLUSTER_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}
_PODS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "pods.eks.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }
    ],
}


def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


_SIM2REAL_TAG = [{"Key": "sim2real", "Value": "1"}]


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_EKS_CLUSTER_TRUST), Tags=_SIM2REAL_TAG
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_pod_identity_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-pia-role-")
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_PODS_TRUST), Tags=_SIM2REAL_TAG
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _create_vpc_and_subnets(ctx) -> list[str]:
    """A dedicated VPC + >=2 AZ-distinct subnets, owned and cleaned up by this check --
    a freshly provisioned account may have no default VPC at all."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": _SIM2REAL_TAG}])[
        "Vpc"
    ]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    # Zones without an EKS control plane fail cluster creation; they are named by zone ID.
    unsupported = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
    azs = [
        a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"] if a["ZoneId"] not in unsupported
    ]
    subnet_ids = []
    for i, az in enumerate(azs[:3]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _SIM2REAL_TAG}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda subnet_id=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
        subnet_ids.append(subnet_id)
    assert len(subnet_ids) >= 2, f"need >=2 AZ-distinct subnets, found {subnet_ids}"
    return subnet_ids


def _poll_until(probe, predicate, timeout_s, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _create_active_cluster(ctx, role_arn: str, subnet_ids: list[str]):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-cl-")
    # A brand-new IAM role is rejected with InvalidParameterException until it propagates.
    deadline = time.monotonic() + 60.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}, tags={"sim2real": "1"}
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: eks.delete_cluster(name=name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200,
        interval_s=20,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster}")
    return name, cluster


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
