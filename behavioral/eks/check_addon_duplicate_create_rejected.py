"""addon-duplicate-create-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "addon-duplicate-create-rejected"
GROUP = "state-machine"
SERVICES = ["eks"]

ADDON_NAME = "eks-pod-identity-agent"
OTHER_ADDON_NAME = "kube-proxy"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAddon for an addon already on the cluster fails with ResourceInUseException "Addon already
    exists.", the existing addon stays ACTIVE at its version, and a different addon can still be created.
    """
    eks = ctx.client("eks")
    cluster = _create_minimal_cluster(ctx)

    eks.create_addon(clusterName=cluster["name"], addonName=ADDON_NAME)
    ctx.on_cleanup(lambda: _delete_addon_and_wait(eks, cluster["name"], ADDON_NAME))
    created = _wait_addon_status(eks, cluster["name"], ADDON_NAME, "ACTIVE")
    original_version = created["addonVersion"]

    # Break exactly one thing: create the SAME addon a second time.
    code = _expect_rejected(lambda: eks.create_addon(clusterName=cluster["name"], addonName=ADDON_NAME))
    assert code == ("ResourceInUseException", "Addon already exists."), f"expected ResourceInUseException, got {code}"

    # Effect absent: the original addon is unaffected (still ACTIVE, same version).
    described = eks.describe_addon(clusterName=cluster["name"], addonName=ADDON_NAME)["addon"]
    assert described["status"] == "ACTIVE", f"expected ACTIVE after rejected duplicate create, got {described['status']}"
    assert described["addonVersion"] == original_version, (
        f"expected addonVersion to stay {original_version!r} after rejected duplicate create, "
        f"got {described['addonVersion']!r}"
    )

    # Positive control in the same file: a DIFFERENT addon on the same cluster works.
    eks.create_addon(clusterName=cluster["name"], addonName=OTHER_ADDON_NAME, resolveConflicts="OVERWRITE")
    ctx.on_cleanup(lambda: _delete_addon_and_wait(eks, cluster["name"], OTHER_ADDON_NAME))
    control = _wait_addon_status(eks, cluster["name"], OTHER_ADDON_NAME, "ACTIVE")
    assert control["addonName"] == OTHER_ADDON_NAME, (
        f"expected the positive-control addon to be {OTHER_ADDON_NAME!r}, got {control['addonName']!r}"
    )


def _gone(fn) -> bool:
    """Call fn; True when it raises ResourceNotFoundException, False when it succeeds. Any
    other error propagates."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _delete_with_retry(fn, attempts: int = 5, delay_s: float = 8.0) -> None:
    """Retry a teardown call past EKS's ENI-detachment lag: a VPC/subnet delete can hit
    DependencyViolation for a short while after the cluster that used them is gone."""
    from botocore.exceptions import ClientError

    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("DependencyViolation", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
                if i == attempts - 1:
                    return
                time.sleep(delay_s)
                continue
            raise


def _expect_rejected(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _wait_addon_status(eks: Any, cluster_name: str, addon_name: str, want: str, timeout_s: float = 900.0, interval_s: float = 10.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        addon = eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"]
        last = addon["status"]
        if last == want:
            return addon
        if last.endswith("_FAILED"):
            raise AssertionError(f"addon {addon_name} entered {last}")
        time.sleep(interval_s)
    raise AssertionError(f"addon {addon_name} did not reach {want} within {timeout_s}s (last={last})")


def _delete_addon_and_wait(eks: Any, cluster_name: str, addon_name: str, timeout_s: float = 600.0, interval_s: float = 10.0) -> None:
    _gone(lambda: eks.delete_addon(clusterName=cluster_name, addonName=addon_name))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _gone(lambda: eks.describe_addon(clusterName=cluster_name, addonName=addon_name)):
            return
        time.sleep(interval_s)
    raise AssertionError(f"addon {addon_name} did not delete within {timeout_s}s")


def _create_minimal_cluster(ctx, authentication_mode: str | None = None) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")

    vpc_id = ec2.create_vpc(CidrBlock="10.74.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.74.{i}.0/24", AvailabilityZone=az
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=sid)))

    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
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
    kwargs: dict[str, Any] = dict(
        name=cluster_name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}
    )
    if authentication_mode:
        kwargs["accessConfig"] = {"authenticationMode": authentication_mode}

    # IAM role propagation is eventually consistent: retry CreateCluster itself, bounded, rather
    # than guessing a fixed delay.
    deadline = time.monotonic() + 90.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            break
        except eks.exceptions.ClientException as exc:
            last_error = exc
            time.sleep(2)
    else:
        raise AssertionError(f"create_cluster never succeeded (IAM role propagation?): {last_error}")

    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, cluster_name))
    _wait_for_cluster_status(eks, cluster_name, "ACTIVE", timeout_s=1200.0)
    return {"name": cluster_name, "role_arn": role_arn, "subnet_ids": subnet_ids, "vpc_id": vpc_id}


def _wait_for_cluster_status(eks: Any, name: str, want: str, timeout_s: float = 1200.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last == want:
            return
        if last == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {want} in {timeout_s}s (last={last})")


def _delete_cluster_and_wait(eks: Any, name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    _gone(lambda: eks.delete_cluster(name=name))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _gone(lambda: eks.describe_cluster(name=name)):
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not delete within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
