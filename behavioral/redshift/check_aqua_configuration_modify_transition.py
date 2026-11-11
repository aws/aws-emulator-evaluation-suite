"""aqua-configuration-modify-transition."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "aqua-configuration-modify-transition"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyAquaConfiguration is a retired no-op: the cluster's reported AQUA state is unchanged after
    the call, whatever AquaConfigurationStatus was requested.
    """
    redshift = ctx.client("redshift")
    cluster_id = _create_available_cluster(ctx)

    before = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    aqua_before = before.get("AquaConfiguration", {})

    redshift.modify_aqua_configuration(
        ClusterIdentifier=cluster_id, AquaConfigurationStatus="enabled"
    )

    after = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    aqua_after = after.get("AquaConfiguration", {})

    # The retired operation must not change the reported AQUA state at all.
    assert aqua_after == aqua_before, (
        f"expected AquaConfiguration to be unchanged by the retired "
        f"ModifyAquaConfiguration call, got before={aqua_before!r} after={aqua_after!r}"
    )
    assert after["ClusterStatus"] == "available", (
        f"expected ClusterStatus to remain 'available' after the retired "
        f"ModifyAquaConfiguration call, got {after['ClusterStatus']!r}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _rand_password() -> str:
    return f"S2r{secrets.token_hex(4)}Aa1Xy"


def _default_vpc_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region to build a Redshift cluster subnet "
            "group from; a non-shared network VPC + subnets would need to be provisioned first"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    by_az: dict[str, str] = {}
    for subnet in subnets:
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    if not by_az:
        raise AssertionError("shared network has no subnets available")
    return list(by_az.values())


def _create_available_cluster(ctx) -> str:
    redshift = ctx.client("redshift")
    subnet_ids = _default_vpc_subnets(ctx)
    subnet_group_name = ctx.unique_name("sim2real-subg-")
    redshift.create_cluster_subnet_group(
        ClusterSubnetGroupName=subnet_group_name,
        Description="sim2real behavioral fidelity check",
        SubnetIds=subnet_ids[:2] if len(subnet_ids) > 1 else subnet_ids,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(redshift, subnet_group_name))

    cluster_id = ctx.unique_name("sim2real-clu-")
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(),
        ClusterSubnetGroupName=subnet_group_name,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))

    waiter = redshift.get_waiter("cluster_available")
    try:
        waiter.wait(
            ClusterIdentifier=cluster_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": 900},
        )
    except WaiterError as exc:
        raise AssertionError(f"cluster {cluster_id} never became available: {exc}")
    return cluster_id


def _delete_cluster(redshift, cluster_id: str) -> None:
    try:
        redshift.delete_cluster(
            ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ClusterNotFoundFault":
            return
        raise
    waiter = redshift.get_waiter("cluster_deleted")
    try:
        waiter.wait(
            ClusterIdentifier=cluster_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": 900},
        )
    except WaiterError:
        pass


def _safe_delete_subnet_group(redshift, name: str) -> None:
    import time

    for _ in range(20):
        try:
            redshift.delete_cluster_subnet_group(ClusterSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterSubnetGroupNotFoundFault":
                return
            if code == "InvalidClusterSubnetGroupStateFault":
                time.sleep(15)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
