"""e2e-addon-version-upgrade-consequence-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-addon-version-upgrade-consequence-flow"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Upgrading vpc-cni from an older to a newer compatible version is durable: DescribeUpdate
    reaches Successful and DescribeAddon reports the new addonVersion, not merely a 200."""
    eks = ctx.client("eks")

    subnet_ids = _create_network(ctx)
    cluster_role_arn = _create_role(
        ctx, "cluster", "eks.amazonaws.com", ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]
    )

    cluster_name = ctx.unique_name("sim2real-eks-cl-")
    _create_cluster_with_retry(ctx, cluster_name, cluster_role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _best_effort(lambda: eks.delete_cluster(name=cluster_name)))
    _wait_cluster_status(ctx, cluster_name, {"ACTIVE"}, timeout_s=1200)

    k8s_version = eks.describe_cluster(name=cluster_name)["cluster"]["version"]

    addon_info = eks.describe_addon_versions(addonName="vpc-cni", kubernetesVersion=k8s_version)["addons"]
    if not addon_info or len(addon_info[0].get("addonVersions", [])) < 2:
        raise AssertionError(
            f"fewer than 2 compatible vpc-cni versions advertised for kubernetesVersion="
            f"{k8s_version}; cannot exercise a version upgrade"
        )
    versions = [v["addonVersion"] for v in addon_info[0]["addonVersions"]]
    new_version = versions[0]
    old_version = versions[-1]
    assert old_version != new_version, (
        f"expected two distinct compatible vpc-cni versions, got old={old_version!r} == new={new_version!r}"
    )

    eks.create_addon(
        clusterName=cluster_name,
        addonName="vpc-cni",
        addonVersion=old_version,
        resolveConflicts="OVERWRITE",
    )
    status = _poll_addon_terminal(ctx, cluster_name, "vpc-cni", timeout_s=300)
    assert status != "CREATE_FAILED", f"CreateAddon(vpc-cni, {old_version}) failed"
    created = eks.describe_addon(clusterName=cluster_name, addonName="vpc-cni")["addon"]
    assert created["addonVersion"] == old_version, (
        f"expected freshly-created addon at version={old_version!r}, got {created['addonVersion']!r}"
    )

    update = eks.update_addon(
        clusterName=cluster_name,
        addonName="vpc-cni",
        addonVersion=new_version,
        resolveConflicts="OVERWRITE",
    )["update"]
    final_update_status = _poll_update_terminal(
        ctx, cluster_name, update["id"], addon_name="vpc-cni", timeout_s=300
    )
    assert final_update_status == "Successful", f"UpdateAddon update ended in {final_update_status}"

    upgraded = eks.describe_addon(clusterName=cluster_name, addonName="vpc-cni")["addon"]
    assert upgraded["addonVersion"] == new_version, (
        f"expected durable addonVersion={new_version}, got {upgraded['addonVersion']}"
    )

    eks.delete_addon(clusterName=cluster_name, addonName="vpc-cni")
    _wait_addon_deleted(ctx, cluster_name, "vpc-cni", timeout_s=300)

    eks.delete_cluster(name=cluster_name)
    _wait_cluster_deleted(ctx, cluster_name, timeout_s=900)




def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _delete_with_retry(fn):
    """Run a network delete (_delete_net retries DependencyViolation); an already-gone
    VPC or subnet is a clean teardown, any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
            raise


def _create_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.44.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"] if a["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.44.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-sn{i}-")}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_with_retry(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_role(ctx, kind, trust_service, managed_policy_arns):
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-eks-{kind}-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
        }
    )
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    for policy_arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in managed_policy_arns:
            _best_effort(lambda p=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=p))
        _best_effort(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_cleanup)
    return arn


def _create_cluster_with_retry(ctx, name, role_arn, subnet_ids, timeout_s=90):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            return
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code in ("InvalidParameterException", "ClientException"):
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"create_cluster never succeeded (IAM propagation?): {last_err}")


def _wait_cluster_status(ctx, name, target_statuses, timeout_s, interval_s=15):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} status {last} never reached {target_statuses}")


def _wait_cluster_deleted(ctx, name, timeout_s, interval_s=15):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _wait_addon_deleted(ctx, cluster_name, addon_name, timeout_s, interval_s=10):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_addon(clusterName=cluster_name, addonName=addon_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"addon {addon_name} was not deleted within {timeout_s}s")


def _poll_addon_terminal(ctx, cluster_name, addon_name, timeout_s, interval_s=10):
    eks = ctx.client("eks")
    terminal = {"ACTIVE", "CREATE_FAILED", "DEGRADED", "UPDATE_FAILED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"]["status"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"addon {addon_name} status {last} never reached a terminal state")


def _poll_update_terminal(ctx, cluster_name, update_id, addon_name, timeout_s, interval_s=10):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_update(name=cluster_name, updateId=update_id, addonName=addon_name)["update"]["status"]
        if last != "InProgress":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} status {last} never left InProgress")


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
