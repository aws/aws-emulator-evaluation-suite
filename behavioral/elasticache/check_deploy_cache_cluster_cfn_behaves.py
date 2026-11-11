"""deploy-cache-cluster-cfn-behaves."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cache-cluster-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CacheCluster deployed via CloudFormation reaches available and accepts a live
    ModifyCacheCluster change, proving the stack resource is a functioning cluster beyond
    CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    ec = ctx.client("elasticache")
    ec2 = ctx.client("ec2")

    cluster_id = ctx.unique_name("sim2real-cc-")
    stack_name = ctx.unique_name("sim2real-ccstack-")
    subnet_group_name = _create_subnet_group(ctx, ec, ec2)
    sg_id = _create_security_group(ctx, ec2)

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TestCacheCluster": {
                "Type": "AWS::ElastiCache::CacheCluster",
                "Properties": {
                    "ClusterName": cluster_id,
                    "Engine": "memcached",
                    "CacheNodeType": "cache.t3.micro",
                    "NumCacheNodes": 1,
                    "CacheSubnetGroupName": subnet_group_name,
                    "VpcSecurityGroupIds": [sg_id],
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
                },
            }
        },
    }

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name, ec, cluster_id))

    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
        )
    except Exception:
        reason = _first_failure_reason(cfn, stack_name)
        raise AssertionError(reason) from None
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {stack['StackStatus']}"

    cluster = _poll_until(
        lambda: ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0],
        lambda c: c["CacheClusterStatus"] == "available",
        timeout_s=900,
        interval_s=20,
    )
    assert cluster["CacheClusterStatus"] == "available", f"expected available, got {cluster['CacheClusterStatus']}"
    assert cluster["CacheClusterId"] == cluster_id, f"expected {cluster_id}, got {cluster['CacheClusterId']}"

    # Prove the stack-created resource is a real, live cluster: apply a data-plane-adjacent
    # control-plane change and observe it actually take effect on the resource.
    new_window = "wed:09:00-wed:10:00"
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        PreferredMaintenanceWindow=new_window,
        ApplyImmediately=True,
    )

    updated = _poll_until(
        lambda: ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0],
        lambda c: c.get("PreferredMaintenanceWindow") == new_window
        and c["CacheClusterStatus"] == "available",
        timeout_s=600,
        interval_s=15,
    )
    assert updated["PreferredMaintenanceWindow"] == new_window, (
        f"expected window {new_window!r}, got {updated.get('PreferredMaintenanceWindow')!r}"
    )
    assert updated["CacheClusterStatus"] == "available", f"expected available, got {updated['CacheClusterStatus']}"


def _poll_until(probe, predicate, timeout_s=900, interval_s=15):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_subnet_group(ctx, ec, ec2) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets][:3]
    name = ctx.unique_name("sim2real-ec-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=name))
    return name


def _create_security_group(ctx, ec2) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    name = ctx.unique_name("sim2real-ec-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real elasticache behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return sg_id


def _delete_stack(ctx, stack_name: str, ec, cluster_id: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )
    # The stack teardown must actually take the underlying cluster with it, not just
    # report CFN-side success: confirm via an independent ElastiCache read.
    try:
        ec.describe_cache_clusters(CacheClusterId=cluster_id)
    except ec.exceptions.CacheClusterNotFoundFault as exc:
        err = exc.response["Error"]
        assert err["Code"] == "CacheClusterNotFound", f"expected CacheClusterNotFound, got {err!r}"
        expected = f"CacheCluster not found: {cluster_id}"
        assert err.get("Message") == expected, f"expected {expected!r}, got {err.get('Message')!r}"
    else:
        raise AssertionError(
            f"stack {stack_name} reported deleted but cluster {cluster_id} is still describable"
        )


def _first_failure_reason(cfn, stack_name: str) -> str:
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except Exception as exc:  # noqa: BLE001
        return f"<could not fetch stack events: {exc}>"
    for e in events:
        if e.get("ResourceStatus", "").endswith("FAILED"):
            return f"{e.get('LogicalResourceId')}: {e.get('ResourceStatusReason')}"
    return "<no FAILED event found>"


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
