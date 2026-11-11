"""e2e-addon-upgrade-workload-continuity."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-addon-upgrade-workload-continuity"
GROUP = "state-machine"
SERVICES = ["eks"]

ADDON_NAME = "eks-pod-identity-agent"


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An addon upgraded to a newer version remains ACTIVE with the new version
    reflected end-to-end (DescribeAddon), before it is removed."""
    eks = ctx.client("eks")
    cluster = _create_minimal_cluster(ctx)

    versions_resp = eks.describe_addon_versions(
        addonName=ADDON_NAME, kubernetesVersion=cluster["version"]
    )["addons"]
    all_versions = sorted(
        {v["addonVersion"] for entry in versions_resp for v in entry.get("addonVersions", [])}
    )
    if len(all_versions) < 2:
        raise AssertionError(
            f"fewer than 2 compatible versions of {ADDON_NAME} published for "
            f"kubernetesVersion={cluster['version']} in this account/region; cannot "
            "exercise an upgrade. Would close with a region/version that publishes >=2 versions."
        )
    v1, v2 = all_versions[0], all_versions[-1]
    assert v1 != v2, f"expected two distinct compatible versions, got v1={v1!r} v2={v2!r}"

    eks.create_addon(clusterName=cluster["name"], addonName=ADDON_NAME, addonVersion=v1)
    ctx.on_cleanup(lambda: _delete_addon_and_wait(eks, cluster["name"], ADDON_NAME))
    created = _wait_addon_status(eks, cluster["name"], ADDON_NAME, "ACTIVE")
    assert created["addonVersion"] == v1, f"expected initial version {v1}, got {created['addonVersion']}"

    eks.update_addon(
        clusterName=cluster["name"],
        addonName=ADDON_NAME,
        addonVersion=v2,
        resolveConflicts="OVERWRITE",
    )
    updated = _wait_addon_status(eks, cluster["name"], ADDON_NAME, "ACTIVE")
    assert updated["addonVersion"] == v2, f"expected upgraded version {v2}, got {updated['addonVersion']}"

    _delete_addon_and_wait(eks, cluster["name"], ADDON_NAME)
    code, msg = _error_code(lambda: eks.describe_addon(clusterName=cluster["name"], addonName=ADDON_NAME))
    assert code == "ResourceNotFoundException", f"unexpected code after delete: {code}"
    expected = "The requested resource does not exist."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _error_code(fn):
    """Call fn(); return the (Code, Message) of the error it raises, and raise on success."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


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
    from botocore.exceptions import ClientError

    try:
        eks.delete_addon(clusterName=cluster_name, addonName=addon_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise AssertionError(f"unexpected delete_addon error: {err}") from err
        if err.response["Error"].get("Message") != "The requested resource does not exist.":
            raise AssertionError(f"unexpected delete_addon message: {err}") from err
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_addon(clusterName=cluster_name, addonName=addon_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"addon {addon_name} did not delete within {timeout_s}s")


def _create_minimal_cluster(ctx, authentication_mode: str | None = None) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")

    vpc_id = ec2.create_vpc(CidrBlock="10.72.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.72.{i}.0/24", AvailabilityZone=az
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))

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
    _create_cluster_with_retry(eks, kwargs)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, cluster_name))
    _wait_for_cluster_status(eks, cluster_name, "ACTIVE", timeout_s=1200.0)
    version = eks.describe_cluster(name=cluster_name)["cluster"]["version"]
    return {"name": cluster_name, "role_arn": role_arn, "subnet_ids": subnet_ids, "vpc_id": vpc_id, "version": version}


def _create_cluster_with_retry(eks: Any, kwargs: dict[str, Any], timeout_s: float = 90.0, interval_s: float = 10.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Any = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            return
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code in ("InvalidParameterException", "ClientException"):
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"create_cluster never succeeded (IAM role propagation?): {last_err}")


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
    from botocore.exceptions import ClientError

    try:
        eks.delete_cluster(name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise AssertionError(f"unexpected delete_cluster error: {err}") from err
        if err.response["Error"].get("Message", "").rstrip(".") != f"No cluster found for name: {name}":
            raise AssertionError(f"unexpected delete_cluster message: {err}") from err
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not delete within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
