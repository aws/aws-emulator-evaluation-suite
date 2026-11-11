"""subnet-group-duplicate-fails."""
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


CHECK = "subnet-group-duplicate-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating a cluster subnet group name in use is rejected with ClusterSubnetGroupAlreadyExists
    and its exact message, and the original keeps its description and subnets."""
    rs = ctx.client("redshift")
    ec2 = ctx.client("ec2")
    subnet_ids = _usable_subnet_ids(ec2, limit=2, ctx=ctx)
    group_name = ctx.unique_name("sim2real-behav-rs-sngdup-")
    ctx.on_cleanup(lambda: _delete_absent_ok(
        lambda: rs.delete_cluster_subnet_group(ClusterSubnetGroupName=group_name), "ClusterSubnetGroupNotFoundFault"
    ))
    rs.create_cluster_subnet_group(
        ClusterSubnetGroupName=group_name,
        Description="behavioral fidelity duplicate subnet group",
        SubnetIds=subnet_ids,
    )

    code, message = _error(lambda: rs.create_cluster_subnet_group(
        ClusterSubnetGroupName=group_name,
        Description="behavioral fidelity duplicate subnet group second",
        SubnetIds=subnet_ids[:1],
    ))
    assert code == "ClusterSubnetGroupAlreadyExists", f"expected ClusterSubnetGroupAlreadyExists, got {code}"
    assert message == f"The Cluster subnet group '{group_name}' already exists.", message

    described = rs.describe_cluster_subnet_groups(ClusterSubnetGroupName=group_name)["ClusterSubnetGroups"]
    assert len(described) == 1, described
    survivor = described[0]
    assert survivor["Description"] == "behavioral fidelity duplicate subnet group", (
        "the losing create must not mutate the group's description"
    )
    assert {s["SubnetIdentifier"] for s in survivor["Subnets"]} == set(subnet_ids), (
        "the losing create must not mutate the group's subnet set"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
