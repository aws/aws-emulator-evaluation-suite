"""cache-subnet-group-lifecycle."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(); return (code, message) from the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, message = _error(fn)
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code}"
    assert message == expected[1], f"expected message {expected[1]!r}, got {message!r}"
    return code

def _describe_one(fn, list_key, id_field, id_value, **extra):
    """describe wrapper: return the single item, None on NotFound / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None

def _describe_subnet_group(ec, name):
    return _describe_one(ec.describe_cache_subnet_groups, "CacheSubnetGroups", "CacheSubnetGroupName", name)

def _delete_subnet_group(ec, name, timeout_s=660, interval_s=15):
    """Delete a cache subnet group, retrying while a referencing cluster is still draining."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code") or ""
            if "NotFound" in code:
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _delete_ec2_quietly(fn, not_found_codes, timeout_s=180, interval_s=10):
    """Call an EC2 delete, tolerating the resource already being gone.

    Retries `DependencyViolation`: if this check fails partway through, the cache subnet
    group can still be pointing at our subnet when teardown runs, and EC2 refuses the
    delete until the referencing group is gone.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code") or ""
            if code in not_found_codes:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

def _make_own_subnets(ec2, ctx, count=2):
    """A throwaway VPC with `count` subnets in distinct AZs, owned by this check.

    Does not depend on the account having a default VPC, which an account or region may
    not have. VPCs and subnets are non-billable, so this costs nothing.
    """
    vpc_id = ec2.create_vpc(
        CidrBlock="10.225.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(lambda: ec2.delete_vpc(VpcId=vpc_id), ("InvalidVpcID.NotFound",))
    )
    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[:count]
    if len(azs) < count:
        raise AssertionError(f"region {ctx.region} has only {len(azs)} available AZs; need {count}")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.225.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=subnet_id: _delete_ec2_quietly(
                lambda: ec2.delete_subnet(SubnetId=sid), ("InvalidSubnetID.NotFound",)
            )
        )
        subnet_ids.append(subnet_id)
    return subnet_ids

CHECK = "cache-subnet-group-lifecycle"
GROUP = 'subnet-group'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cache subnet group can be created from real subnets, modified, described, and
    deleted; a duplicate name is rejected; and once deleted, the name is reusable and every
    further operation on it reports the same specific not-found fault."""
    ec = ctx.client("elasticache")
    ec2 = ctx.client("ec2")
    subnet_ids = _make_own_subnets(ec2, ctx, 2)
    name = ctx.unique_name("sim2real-behav-ecsg-")
    created = ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="fidelity check subnet group",
        SubnetIds=subnet_ids,
        Tags=_MANAGED_TAGS,
    )["CacheSubnetGroup"]
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, name))
    got_subnets = {s["SubnetIdentifier"] for s in created["Subnets"]}
    assert got_subnets == set(subnet_ids), f"create echoed {got_subnets}, expected {set(subnet_ids)}"
    assert created.get("VpcId"), created

    group = _describe_subnet_group(ec, name)
    assert group is not None, f"{name} not found immediately after create"
    got_subnets = {s["SubnetIdentifier"] for s in group["Subnets"]}
    assert got_subnets == set(subnet_ids), f"describe returned {got_subnets}, expected {set(subnet_ids)}"

    # ModifyCacheSubnetGroup must replace, not merge, the membership.
    ec.modify_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="fidelity check subnet group modified",
        SubnetIds=[subnet_ids[0]],
    )
    modified = _describe_subnet_group(ec, name)
    assert {s["SubnetIdentifier"] for s in modified["Subnets"]} == {subnet_ids[0]}, modified
    assert modified["CacheSubnetGroupDescription"] == "fidelity check subnet group modified", modified

    # Duplicate name is rejected.
    _assert_error(lambda: ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="dup",
        SubnetIds=subnet_ids,
    ), ("CacheSubnetGroupAlreadyExistsFault", f"Cache subnet group {name} already exists."))

    # Delete proves gone (specific not-found fault, not just an empty read) and unusable
    # (a mutation on the dead id fails with the SAME fault); the name is then reusable.
    ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
    not_found_code = _assert_error(
        lambda: ec.describe_cache_subnet_groups(CacheSubnetGroupName=name),
        ("CacheSubnetGroupNotFoundFault",
        f"Cache subnet group {name} not found."),
    )
    dead_code = _assert_error(
        lambda: ec.modify_cache_subnet_group(CacheSubnetGroupName=name, SubnetIds=[subnet_ids[0]]),
        (not_found_code,
        f"Cache Subnet Group {name} does not exist."),
    )
    assert dead_code == not_found_code, (
        f"modify on a deleted group: expected the same fault as describe ({not_found_code}), "
        f"got {dead_code}"
    )

    recreated = ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="fidelity check subnet group reused",
        SubnetIds=subnet_ids,
        Tags=_MANAGED_TAGS,
    )["CacheSubnetGroup"]
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, name))
    assert recreated.get("CacheSubnetGroupName") == name, (
        f"deleted name {name} was not reusable: recreate returned {recreated}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
