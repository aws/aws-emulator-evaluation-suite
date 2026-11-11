"""capability-create-malformed-input-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capability-create-malformed-input-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapability with a `type` outside ACK | KRO | ARGOCD on an ACTIVE cluster is rejected
    with InvalidParameterException and creates nothing, while the same role and cluster succeed
    with KRO."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    capability_role_arn = _create_capability_role(ctx)

    bogus_capability_name = ctx.unique_name("sim2real-cap-")

    err = _error(
        lambda: eks.create_capability(
            clusterName=cluster_name,
            capabilityName=bogus_capability_name,
            type="NOT_A_REAL_CAPABILITY_TYPE",
            roleArn=capability_role_arn,
            deletePropagationPolicy="RETAIN",
        )
    )
    assert err == ("InvalidParameterException", "Invalid capability type"), f"expected InvalidParameterException, got {err!r}"

    capabilities = eks.list_capabilities(clusterName=cluster_name)["capabilities"]
    assert all(c.get("capabilityName") != bogus_capability_name for c in capabilities), (
        f"rejected create must not persist a capability: {capabilities}"
    )

    # positive control: the identical role and cluster succeed for a real, supported
    # type, so the rejection above is provably about the `type` value and not about a
    # bad role trust policy or a capabilities surface that is dead for every call.
    good_name = ctx.unique_name("sim2real-cap-kro-")
    created = _retry_on_client_error(
        lambda: eks.create_capability(
            clusterName=cluster_name,
            capabilityName=good_name,
            type="KRO",
            roleArn=capability_role_arn,
            deletePropagationPolicy="RETAIN",
        )["capability"],
        timeout_s=90.0,
        interval_s=5.0,
    )
    ctx.on_cleanup(lambda: _delete_capability_and_wait(eks, cluster_name, good_name))
    assert created["type"] == "KRO", created
    assert created["capabilityName"] == good_name, created


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn, require it raises ClientError, return its (Code, Message)."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


def _cluster_subnets(ctx, min_subnets: int = 2) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())
        if len(subnet_ids) >= min_subnets:
            return subnet_ids[:3]
    return _create_own_vpc_subnets(ctx, min_subnets)


def _create_own_vpc_subnets(ctx, min_subnets: int) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:min_subnets]
    if len(azs) < min_subnets:
        raise AssertionError(f"region has fewer than {min_subnets} available AZs to host a test EKS cluster")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "sim2real:managed", "Value": "true"}])
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _retry_on_client_error(fn: Callable[[], Any], timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_capability_role(ctx) -> str:
    # A capability role must trust the capabilities service principal (not eks.amazonaws.com)
    # with both sts:AssumeRole and sts:TagSession.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-caprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "capabilities.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_eks_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_active_cluster(ctx, version: str | None = None) -> str:
    eks = ctx.client("eks")
    subnet_ids = _cluster_subnets(ctx)
    role_arn = _create_eks_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "resourcesVpcConfig": {"subnetIds": subnet_ids},
        # CreateCapability requires access entries, which require the cluster's
        # authenticationMode to be API or API_AND_CONFIG_MAP.
        "accessConfig": {"authenticationMode": "API"},
    }
    if version:
        kwargs["version"] = version

    deadline = time.monotonic() + 90.0
    while True:
        try:
            eks.create_cluster(**kwargs)
            break
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"cluster role {role_arn} never became assumable by eks.amazonaws.com within 90s: {exc}"
                ) from exc
            time.sleep(5)  # freshly-created IAM role/trust-policy propagation lag
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster}")
    return name


def _delete_capability_and_wait(eks, cluster_name: str, capability_name: str, timeout_s: float = 900.0) -> None:
    """Teardown: DeleteCapability is asynchronous, and DeleteCluster refuses a cluster that still
    has capabilities attached, so wait until the capability reads not-found."""
    try:
        eks.delete_capability(clusterName=cluster_name, capabilityName=capability_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_capability(clusterName=cluster_name, capabilityName=capability_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"capability {capability_name} still present {timeout_s}s after DeleteCapability")



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network;
    ResourceInUseException (an update, node group or add-on still running) is retried."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
