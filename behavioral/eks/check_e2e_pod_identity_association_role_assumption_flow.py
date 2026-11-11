"""e2e-pod-identity-association-role-assumption-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-pod-identity-association-role-assumption-flow"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:e2e", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associate a service account with an IAM role via pod identity, assume the role and
    confirm caller identity reflects the mapped role, then delete and confirm the mapping
    no longer resolves."""
    vpc = _create_vpc_infra(ctx)
    cluster_role_arn = _create_cluster_role(ctx)
    cluster_name = ctx.unique_name("sim2real-eks-pidf-")
    _create_cluster_via_sdk(ctx, cluster_name, cluster_role_arn, vpc["subnet_ids"])

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    pod_role_name, pod_role_arn = _create_pod_identity_role(ctx, account_id)

    eks = ctx.client("eks")
    namespace = "sim2real-flow-ns"
    service_account = "sim2real-flow-sa"
    assoc = eks.create_pod_identity_association(
        clusterName=cluster_name, namespace=namespace, serviceAccount=service_account, roleArn=pod_role_arn
    )["association"]
    association_id = assoc["associationId"]

    def _cleanup_assoc():
        try:
            eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "response", {}).get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_assoc)

    described = eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)["association"]
    assert described["roleArn"] == pod_role_arn, (
        f"expected association {association_id} bound to {pod_role_arn}, got {described['roleArn']}"
    )

    creds = _assume_role_with_retry(sts, pod_role_arn, "sim2real-pidf-session")
    assumed_client = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    identity = assumed_client.get_caller_identity()
    expected_arn = f"arn:aws:sts::{account_id}:assumed-role/{pod_role_name}/sim2real-pidf-session"
    assert identity["Arn"] == expected_arn, (
        f"expected assumed-role identity {expected_arn}, got {identity['Arn']}"
    )

    eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    code = msg = None
    for _ in range(10):
        try:
            eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)
            time.sleep(2)
        except Exception as exc:  # noqa: BLE001
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message")
            break
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code!r}"
    )
    expected = f"No service account role association found for ID: {association_id}"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _retry_delete(fn, attempts: int = 12, delay_s: float = 10.0) -> None:
    last_exc = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(delay_s)
    if last_exc is not None:
        raise last_exc


def _assume_role_with_retry(sts_client, role_arn: str, session_name: str, timeout_s: float = 90.0, interval_s: float = 5.0) -> dict:
    """AssumeRole, retrying AccessDenied while a just-created role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "AccessDenied":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"assume_role on {role_arn} still denied after {timeout_s}s (IAM propagation): {last_exc}")


def _create_vpc_infra(ctx) -> dict:
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        subnet_ids = sorted({s["SubnetId"] for s in subnets})[:3]
        if len(subnet_ids) >= 2:
            return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}

    # No usable shared network: create a minimal one for this cluster.
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.90.{i}.0/24", AvailabilityZone=az)[
            "Subnet"
        ]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    if len(subnet_ids) < 2:
        raise AssertionError(f"could not provision >=2 AZ subnets for EKS (found {len(subnet_ids)})")
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-cluster-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _create_pod_identity_role(ctx, account_id: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-podid-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_name, role_arn


def _create_cluster_via_sdk(ctx, name: str, role_arn: str, subnet_ids: list[str]) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))
    _wait_cluster_status(ctx, name, "ACTIVE", timeout_s=1200)


def _wait_cluster_status(ctx, name: str, target: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        last_status = cluster["status"]
        if last_status == target:
            return cluster
        if last_status in ("FAILED",):
            raise AssertionError(f"cluster {name} entered terminal status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s (last={last_status})")


def _delete_cluster_and_wait(ctx, name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    try:
        _delete_eks_cluster_retrying(eks, name)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


# EC2 network teardown waits for AWS-managed ENIs to leave before deleting: dependents in the VPC
# delete asynchronously, so an immediate DeleteSubnet/DeleteVpc fails with DependencyViolation.
# The bounded window is shared by all of one check's network deletes and fits the cleanup budget.
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


def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
