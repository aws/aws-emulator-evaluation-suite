"""create-db-cluster-reaches-available."""
from __future__ import annotations

import secrets
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-db-cluster-reaches-available"
GROUP = "overly-permissive"
SERVICES = ["timestream-influxdb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDbCluster (MULTI_NODE_READ_REPLICAS, the only ClusterDeploymentType) without a Read Replicas Marketplace
    subscription fails with ValidationException and the exact subscription message, while CreateDbParameterGroup
    succeeds as the control."""
    influx = ctx.client("timestream-influxdb")

    pg_name = ctx.unique_name("sim2real-cluster-pg-")
    pg = influx.create_db_parameter_group(name=pg_name, description="sim2real positive control")
    assert pg["name"] == pg_name, (
        f"positive control: expected CreateDbParameterGroup to echo name {pg_name!r}, got {pg['name']!r}"
    )

    net = _ensure_network(ctx)
    name = ctx.unique_name("sim2real-cluster-")
    created = None
    try:
        created = influx.create_db_cluster(
            name=name,
            username="sim2realadmin",
            password=secrets.token_hex(12),
            organization="sim2realorg",
            bucket="sim2real-bucket",
            dbInstanceType="db.influx.medium",
            vpcSubnetIds=net["subnet_ids"],
            vpcSecurityGroupIds=[net["security_group_id"]],
            allocatedStorage=20,
            dbStorageType="InfluxIOIncludedT1",
            deploymentType="MULTI_NODE_READ_REPLICAS",
            networkType="IPV4",
            tags={"sim2real": CHECK},
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        assert code == "ValidationException", (
            f"expected ValidationException for the missing Read Replicas Marketplace "
            f"entitlement, got {code!r}: {message!r}"
        )
        expected_message = (
            "Timestream for InfluxDB didn't find an active AWS Marketplace subscription for "
            "Read Replicas associated with the account. You must first create a subscription in "
            "Marketplace to access Read replicas availability settings. You might need to wait "
            "up to 5 minutes for that subscription to be active."
        )
        assert message == expected_message, (
            f"expected message {expected_message!r}, got {message!r}"
        )
    else:
        cluster_id = created["dbClusterId"]
        ctx.on_cleanup(lambda: _delete_cluster_if_present(ctx, cluster_id))
        raise AssertionError(
            "CreateDbCluster succeeded — this sandbox now carries (or AWS no longer "
            "requires) an AWS Marketplace subscription for Read Replicas; the cluster "
            f"{cluster_id!r} this check created is queued for cleanup, and this check "
            "needs to be rewritten back to a happy-path lifecycle assertion"
        )

    listed = influx.list_db_clusters()["items"]
    assert not any(c["name"] == name for c in listed), (
        f"expected no db cluster named {name!r} after the rejected CreateDbCluster, "
        f"found one in ListDbClusters: {listed!r}"
    )


def _delete_cluster_if_present(ctx, cluster_id):
    from botocore.exceptions import ClientError

    influx = ctx.client("timestream-influxdb")
    try:
        influx.delete_db_cluster(dbClusterId=cluster_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _ensure_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region to provision Timestream for InfluxDB "
            "networking prerequisites (would need a custom VPC/subnet/route-table setup)"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if len(subnets) < 2:
        raise AssertionError("shared network does not have at least 2 shared-network subnets")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sg_name = ctx.unique_name("sim2real-influxdb-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name, Description="sim2real timestream-influxdb behavioral check", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "security_group_id": sg_id}


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
