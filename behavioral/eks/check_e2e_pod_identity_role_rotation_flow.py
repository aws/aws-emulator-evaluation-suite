"""e2e-pod-identity-role-rotation-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pod-identity-role-rotation-flow"
GROUP = "e2e"
SERVICES = ["eks"]

_SIM2REAL_TAGS = {"sim2real": "1"}
_SIM2REAL_IAM_TAGS = [{"Key": "sim2real", "Value": "1"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePodIdentityAssociation actually rotates the IAM role bound to a namespace
    + service account: the described association reflects the new roleArn (and only the
    new one), with modifiedAt strictly moving forward, end to end."""
    eks = ctx.client("eks")
    subnet_ids = _create_two_az_subnets(ctx)
    cluster_role_arn = _create_role(ctx, "eks.amazonaws.com", ["AmazonEKSClusterPolicy"])
    role_a_arn = _create_pod_identity_role(ctx)
    role_b_arn = _create_pod_identity_role(ctx)

    cluster_name = ctx.unique_name("sim2real-eks-pia-")
    _create_cluster_with_retry(eks, cluster_name, cluster_role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, eks, cluster_name))
    _wait_cluster_status(ctx, eks, cluster_name, "ACTIVE", timeout_s=1500)

    association = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace="sim2real-ns",
        serviceAccount="sim2real-sa",
        roleArn=role_a_arn,
        tags=_SIM2REAL_TAGS,
    )["association"]
    association_id = association["associationId"]
    ctx.on_cleanup(lambda: _safe_delete_pod_identity(ctx, eks, cluster_name, association_id))

    described = eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)[
        "association"
    ]
    assert described["roleArn"] == role_a_arn, (
        f"association should be bound to role_a {role_a_arn!r} right after creation, got {described['roleArn']!r}"
    )
    modified_before = described["modifiedAt"]

    eks.update_pod_identity_association(clusterName=cluster_name, associationId=association_id, roleArn=role_b_arn)

    updated = eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)[
        "association"
    ]
    assert updated["roleArn"] == role_b_arn, "UpdatePodIdentityAssociation did not rotate the role end to end"
    assert updated["roleArn"] != role_a_arn, (
        f"association still reports the pre-rotation role {role_a_arn!r} after rotating to {role_b_arn!r}"
    )
    assert updated["modifiedAt"] > modified_before, (
        f"modifiedAt did not strictly advance after the role rotation: before={modified_before!r} "
        f"after={updated['modifiedAt']!r}"
    )


# ===== helpers =====

def _create_two_az_subnets(ctx) -> list[str]:
    """Create the VPC and the two subnets the cluster runs in; each registers its cleanup."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-pia-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ][:2]
    ]
    if len(azs) < 2:
        raise AssertionError(f"region does not offer 2 availability zones (got {azs!r})")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name("sim2real-eks-pia-subnet-"))],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return subnet_ids


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}, *_SIM2REAL_IAM_TAGS]}


def _create_role(ctx, service_principal: str, managed_policy_names: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_SIM2REAL_IAM_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name, managed_policy_names))
    for policy_name in managed_policy_names:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
    return role_arn


def _create_pod_identity_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-podrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_SIM2REAL_IAM_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name, []))
    return role_arn


def _safe_delete_role(ctx, role_name: str, managed_policy_names: list[str]) -> None:
    iam = ctx.client("iam")
    for policy_name in managed_policy_names:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_cluster_with_retry(eks, name: str, role_arn: str, subnet_ids: list[str], timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}, tags=_SIM2REAL_TAGS
            )
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ClientException":
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"CreateCluster kept failing with {last_code} after {timeout_s}s (IAM role propagation?)")


def _wait_cluster_status(ctx, eks, name: str, want: str, timeout_s: float, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last == want:
            return
        if last == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {want} within {timeout_s}s (last={last})")


def _cluster_exists(eks, name: str) -> bool:
    try:
        eks.describe_cluster(name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return True


def _safe_delete_cluster(ctx, eks, name: str, timeout_s: float = 1200.0) -> None:
    # DeleteCluster refuses with ResourceInUseException while an update is in progress;
    # retry inside the same window, then wait for the cluster to be gone so the network
    # teardown that follows finds its ENIs released.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(20.0)
    while time.monotonic() < deadline and _cluster_exists(eks, name):
        time.sleep(15.0)


def _safe_delete_pod_identity(ctx, eks, cluster_name: str, association_id: str) -> None:
    try:
        eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
