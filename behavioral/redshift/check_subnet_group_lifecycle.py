"""subnet-group-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _error(fn):
    """Call *fn* and return the (code, message) of the AWS error it raises; a success fails."""
    try:
        _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("the call succeeded where AWS rejects it")


def _usable_subnet_ids(ec2, limit=3, *, ctx):
    """Subnet ids (one per AZ) from the shared network, for subnet-group checks."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    by_az = {}
    for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    ids = list(by_az.values())[:limit]
    if not ids:
        raise AssertionError(f"VPC {vpc_id} has no subnets for cluster-subnet-group checks")
    return ids


def _delete_absent_ok(delete, gone_code):
    """Teardown: the subnet group delete is synchronous; one that was never created answers *gone_code*."""
    try:
        delete()
    except ClientError as exc:
        if _code_of(exc) != gone_code:
            raise


CHECK = "subnet-group-lifecycle"
GROUP = 'networking'
SERVICES = ['redshift']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Cluster subnet groups: create registers the VPC + subnets, modify replaces the set, and after
    delete Describe and Modify answer ClusterSubnetGroupNotFoundFault with their exact messages."""
    rs = ctx.client("redshift")
    ec2 = ctx.client("ec2")
    subnet_ids = _usable_subnet_ids(ec2, limit=3, ctx=ctx)
    group_name = ctx.unique_name("sim2real-behav-rs-sng-")
    ctx.on_cleanup(lambda: _delete_absent_ok(
        lambda: rs.delete_cluster_subnet_group(ClusterSubnetGroupName=group_name), "ClusterSubnetGroupNotFoundFault"
    ))

    created = rs.create_cluster_subnet_group(
        ClusterSubnetGroupName=group_name,
        Description="behavioral fidelity check subnet group",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )["ClusterSubnetGroup"]
    assert created["ClusterSubnetGroupName"] == group_name, (
        f"expected group name {group_name!r}, got {created['ClusterSubnetGroupName']!r}"
    )
    assert created["SubnetGroupStatus"] == "Complete", created
    assert created["VpcId"].startswith("vpc-"), f"expected a vpc-* id, got {created['VpcId']!r}"
    assert {s["SubnetIdentifier"] for s in created["Subnets"]} == set(subnet_ids), (
        f"expected subnets {set(subnet_ids)}, got {[s['SubnetIdentifier'] for s in created['Subnets']]}"
    )
    for subnet in created["Subnets"]:
        assert subnet["SubnetStatus"] == "Active", subnet

    described = rs.describe_cluster_subnet_groups(ClusterSubnetGroupName=group_name)["ClusterSubnetGroups"]
    assert len(described) == 1, described

    modified = rs.modify_cluster_subnet_group(
        ClusterSubnetGroupName=group_name,
        Description="behavioral fidelity updated description",
        SubnetIds=subnet_ids[:1],
    )["ClusterSubnetGroup"]
    assert modified["Description"] == "behavioral fidelity updated description", (
        f"expected updated description, got {modified['Description']!r}"
    )
    assert {s["SubnetIdentifier"] for s in modified["Subnets"]} == set(subnet_ids[:1]), (
        "modify must REPLACE the subnet set, not union it"
    )

    rs.delete_cluster_subnet_group(ClusterSubnetGroupName=group_name)
    code, message = _error(lambda: rs.describe_cluster_subnet_groups(ClusterSubnetGroupName=group_name))
    assert code == "ClusterSubnetGroupNotFoundFault", f"expected ClusterSubnetGroupNotFoundFault, got {code}"
    assert message == f"Cluster Subnet group '{group_name}' not found.", message

    mutate_code, mutate_message = _error(lambda: rs.modify_cluster_subnet_group(
        ClusterSubnetGroupName=group_name,
        SubnetIds=subnet_ids[:1],
    ))
    assert mutate_code == "ClusterSubnetGroupNotFoundFault", (
        f"a mutation on the deleted group must also be rejected, got {mutate_code}"
    )
    assert mutate_message == f"Cluster subnet group '{group_name}' does not exist.", mutate_message

    recreated = rs.create_cluster_subnet_group(
        ClusterSubnetGroupName=group_name,
        Description="behavioral fidelity check subnet group (reused name)",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )["ClusterSubnetGroup"]
    assert recreated["ClusterSubnetGroupName"] == group_name, (
        "a deleted subnet group's name must be reusable, got "
        f"{recreated['ClusterSubnetGroupName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
