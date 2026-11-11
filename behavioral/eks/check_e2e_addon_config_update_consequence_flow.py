"""e2e-addon-config-update-consequence-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-addon-config-update-consequence-flow"
GROUP = "e2e"
SERVICES = ["eks"]

_ADDON_NAME = "coredns"


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Install an addon with initial config, update its config, and observe the applied
    configuration change as a real consequence (DescribeAddon reflects the new value)
    before teardown."""
    vpc = _create_vpc_infra(ctx)
    cluster_role_arn = _create_cluster_role(ctx)
    node_role_arn = _create_node_role(ctx)

    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-addon-")
    cluster = _create_cluster_via_sdk(
        ctx,
        cluster_name,
        cluster_role_arn,
        vpc["subnet_ids"],
        # The self-managed vpc-cni and kube-proxy are what let the node group's nodes join and
        # become Ready; without them the node group never leaves CREATING.
        bootstrap_self_managed_addons=True,
        tags={"sim2real": CHECK},
    )
    cluster_version = cluster["version"]

    # A running node is needed for the coredns Deployment to actually roll out and for the
    # addon's health monitoring to settle on ACTIVE rather than staying degraded.
    nodegroup_name = ctx.unique_name("sim2real-eks-addon-ng-")
    eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        subnets=vpc["subnet_ids"],
        nodeRole=node_role_arn,
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
        instanceTypes=["t3.medium"],
        amiType="AL2023_x86_64_STANDARD",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_nodegroup_and_wait(ctx, cluster_name, nodegroup_name))
    _wait_nodegroup_status(ctx, cluster_name, nodegroup_name, "ACTIVE", timeout_s=1500)

    addon_versions = eks.describe_addon_versions(addonName=_ADDON_NAME, kubernetesVersion=cluster_version)["addons"][0][
        "addonVersions"
    ]
    version = addon_versions[0]["addonVersion"]

    schema = json.loads(eks.describe_addon_configuration(addonName=_ADDON_NAME, addonVersion=version)["configurationSchema"])
    prop = _pick_int_property(schema)

    eks.create_addon(
        clusterName=cluster_name,
        addonName=_ADDON_NAME,
        addonVersion=version,
        configurationValues=json.dumps({prop: 1}),
        resolveConflicts="OVERWRITE",
    )
    ctx.on_cleanup(lambda: _delete_addon_and_wait(ctx, cluster_name, _ADDON_NAME))
    addon = _wait_addon_status(ctx, cluster_name, _ADDON_NAME, "ACTIVE", timeout_s=500)
    assert json.loads(addon["configurationValues"] or "{}") == {prop: 1}, (
        f"addon configurationValues after create did not match the requested {{{prop!r}: 1}}: "
        f"{addon['configurationValues']!r}"
    )

    update_id = eks.update_addon(
        clusterName=cluster_name,
        addonName=_ADDON_NAME,
        configurationValues=json.dumps({prop: 2}),
        resolveConflicts="OVERWRITE",
    )["update"]["id"]
    _wait_update_successful(ctx, cluster_name, update_id, addon_name=_ADDON_NAME, timeout_s=400)

    addon_after = _wait_addon_status(ctx, cluster_name, _ADDON_NAME, "ACTIVE", timeout_s=400)
    assert json.loads(addon_after["configurationValues"] or "{}") == {prop: 2}, (
        f"addon configurationValues did not converge to the update: {addon_after['configurationValues']!r}"
    )


def _pick_int_property(schema: dict) -> str:
    # The published schema can be a bare {"$ref": "#/definitions/<Name>"} over its definitions.
    ref = schema.get("$ref", "")
    if not schema.get("properties") and ref.startswith("#/definitions/"):
        schema = schema.get("definitions", {}).get(ref.split("/")[-1], {})
    props = schema.get("properties", {})
    if "replicaCount" in props:
        return "replicaCount"
    for key, val in props.items():
        if isinstance(val, dict) and val.get("type") == "integer":
            return key
    raise AssertionError(f"no integer configuration property found in addon schema properties: {list(props)}")


_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _create_vpc_infra(ctx) -> dict:
    """Subnets of the run's shared network in distinct, EKS-supported availability zones."""
    net = ctx.network()
    ec2 = ctx.client("ec2")
    zone_ids = {
        z["ZoneName"]: z["ZoneId"]
        for z in ec2.describe_availability_zones(ZoneNames=list(net.availability_zones))["AvailabilityZones"]
    }
    subnet_ids = [net.subnets[az] for az in net.availability_zones if zone_ids[az] not in _BAD_AZS][:3]
    if len(subnet_ids) < 2:
        raise AssertionError(
            f"the shared network {net.vpc_id} does not have subnets in enough EKS-supported "
            f"availability zones (need >=2, found {len(subnet_ids)})"
        )
    return {"vpc_id": net.vpc_id, "subnet_ids": subnet_ids, "sg_id": None}


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


def _create_node_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-node-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policies = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    ]

    def _cleanup():
        """Detach every policy, then delete the role; only an already-absent one is tolerated,
        and a failed detach is raised after the others have run."""
        failed = []
        for p in policies:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
            except iam.exceptions.NoSuchEntityException:
                pass
            except Exception as exc:  # noqa: BLE001 - collected and raised below
                failed.append(f"detach {p}: {exc!r}")
        try:
            iam.delete_role(RoleName=role_name)
        except iam.exceptions.NoSuchEntityException:
            pass
        if failed:
            raise RuntimeError(f"node role {role_name} teardown failed: {'; '.join(failed)}")

    ctx.on_cleanup(_cleanup)
    for p in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=p)
    return role_arn


def _create_cluster_via_sdk(
    ctx,
    name: str,
    role_arn: str,
    subnet_ids: list[str],
    bootstrap_self_managed_addons: bool = True,
    tags: dict[str, str] | None = None,
) -> dict:
    eks = ctx.client("eks")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                bootstrapSelfManagedAddons=bootstrap_self_managed_addons,
                tags=tags or {},
            )
            break
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))
    return _wait_cluster_status(ctx, name, "ACTIVE", timeout_s=1200)


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
        eks.delete_cluster(name=name)
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


def _wait_nodegroup_status(ctx, cluster_name: str, nodegroup_name: str, target: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> dict:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
        last_status = ng["status"]
        if last_status == target:
            return ng
        if last_status in ("CREATE_FAILED", "DELETE_FAILED"):
            raise AssertionError(f"nodegroup {nodegroup_name} entered terminal status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} did not reach {target} within {timeout_s}s (last={last_status})")


def _delete_nodegroup_and_wait(ctx, cluster_name: str, nodegroup_name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"nodegroup {nodegroup_name} was not deleted within {timeout_s}s")


def _wait_addon_status(ctx, cluster_name: str, addon_name: str, target: str, timeout_s: float = 500.0, interval_s: float = 10.0) -> dict:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        addon = eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"]
        last_status = addon["status"]
        if last_status == target:
            return addon
        if last_status in ("CREATE_FAILED", "DELETE_FAILED", "UPDATE_FAILED"):
            raise AssertionError(f"addon {addon_name} entered terminal status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"addon {addon_name} did not reach {target} within {timeout_s}s (last={last_status})")


def _delete_addon_and_wait(ctx, cluster_name: str, addon_name: str, timeout_s: float = 400.0, interval_s: float = 10.0) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_addon(clusterName=cluster_name, addonName=addon_name)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_addon(clusterName=cluster_name, addonName=addon_name)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"addon {addon_name} was not deleted within {timeout_s}s")


def _wait_update_successful(ctx, cluster_name: str, update_id: str, nodegroup_name: str | None = None, addon_name: str | None = None, timeout_s: float = 400.0, interval_s: float = 10.0) -> dict:
    eks = ctx.client("eks")
    kwargs = {"name": cluster_name, "updateId": update_id}
    if nodegroup_name:
        kwargs["nodegroupName"] = nodegroup_name
    if addon_name:
        kwargs["addonName"] = addon_name
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        update = eks.describe_update(**kwargs)["update"]
        last_status = update["status"]
        if last_status == "Successful":
            return update
        if last_status == "Failed":
            raise AssertionError(f"update {update_id} failed: {update.get('errors')}")
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} did not reach Successful within {timeout_s}s (last={last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
