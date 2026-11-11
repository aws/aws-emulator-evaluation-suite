"""subnet-group-invalid-subnet-fails."""

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
    """Call *fn*, retrying only on API throttling, which is not a behavioral observation."""
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
    """Call *fn* (retrying throttles); return (code, message) of the ClientError it raises.
    A call that succeeds raises AssertionError, so it cannot read as a code mismatch."""
    try:
        result = _retrying(fn)
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _usable_subnet_ids(ec2, limit=1, *, ctx):
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

CHECK = "subnet-group-invalid-subnet-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateClusterSubnetGroup rejects a well-formed but nonexistent subnet id with
    InvalidParameterValue and leaves no group; a control with a real subnet succeeds."""
    rs = ctx.client("redshift")
    ec2 = ctx.client("ec2")
    subnet_ids = _usable_subnet_ids(ec2, limit=1, ctx=ctx)
    control_name = ctx.unique_name("sim2real-behav-rs-sngctrl-")
    ctx.on_cleanup(lambda: rs.delete_cluster_subnet_group(ClusterSubnetGroupName=control_name))
    control = rs.create_cluster_subnet_group(
        ClusterSubnetGroupName=control_name,
        Description="behavioral fidelity positive control subnet group",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )["ClusterSubnetGroup"]
    assert control["SubnetGroupStatus"] == "Complete", control

    bad_name = ctx.unique_name("sim2real-behav-rs-sngbad-")
    code, message = _error(lambda: rs.create_cluster_subnet_group(
        ClusterSubnetGroupName=bad_name,
        Description="behavioral fidelity invalid subnet check",
        SubnetIds=["subnet-0123456789abcdef0"],
    ))
    assert code == "InvalidParameterValue", code
    expected_message = "Some input subnets in :[subnet-0123456789abcdef0] are invalid."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    lookup, lookup_message = _error(
        lambda: rs.describe_cluster_subnet_groups(ClusterSubnetGroupName=bad_name)
    )
    assert lookup == "ClusterSubnetGroupNotFoundFault", (
        f"rejected create must not leave a subnet group behind, got {lookup}"
    )
    expected_lookup = f"Cluster Subnet group '{bad_name}' not found."
    assert lookup_message == expected_lookup, (
        f"expected message {expected_lookup!r}, got {lookup_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
