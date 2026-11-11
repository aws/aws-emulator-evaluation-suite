"""subnet-group-replace-semantics-and-cross-vpc-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-group-replace-semantics-and-cross-vpc-rejected"
GROUP = 'subnet-group'
SERVICES = ['elasticache']

_FOREIGN_VPC_CIDR = "10.223.0.0/16"
_FOREIGN_SUBNET_CIDR = "10.223.1.0/24"


def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so an over-permissive target is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _assert_error(fn, expected, what):
    """Assert fn() fails with `expected` (Fault/Exception-suffix normalized); return (code, message)."""
    code, message = _error_code(fn)
    assert code is not None, f"{what}: expected {expected} but the call SUCCEEDED (over-permissive)"
    assert _fault_base(code) == _fault_base(expected), (
        f"{what}: expected {expected}, got {code} ({message!r})"
    )
    return code, message


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
    return _describe_one(
        ec.describe_cache_subnet_groups, "CacheSubnetGroups", "CacheSubnetGroupName", name
    )


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


def _default_subnets_by_az(ec2, count, *, ctx):
    """`count` default-VPC subnet ids in distinct AZs; raises (never skips) if the account has fewer."""
    resp = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )
    by_az = {}
    for subnet in resp.get("Subnets", []):
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    ids = [by_az[az] for az in sorted(by_az)][:count]
    if len(ids) < count:
        raise AssertionError(
            f"account has only {len(by_az)} shared-network subnets in distinct AZs; "
            f"this check needs {count} to prove replace-not-merge semantics"
        )
    return ids


def _delete_ec2_quietly(fn, not_found_codes, timeout_s=180, interval_s=10):
    """Call an EC2 delete, tolerating the resource already being gone.

    Retries `DependencyViolation`: the cache subnet group can still reference the throwaway
    subnet when teardown runs, and EC2 refuses the delete until that group is gone.
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


def _make_foreign_vpc(ec2, ctx):
    """A throwaway VPC + one subnet in it, with teardown registered in reverse order.

    It supplies a subnet id that is real but belongs to a different VPC.
    """
    vpc_id = ec2.create_vpc(
        CidrBlock=_FOREIGN_VPC_CIDR,
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ecvpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(
            lambda: ec2.delete_vpc(VpcId=vpc_id), ("InvalidVpcID.NotFound",)
        )
    )
    az = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_FOREIGN_SUBNET_CIDR,
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ecsub-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(
            lambda: ec2.delete_subnet(SubnetId=subnet_id), ("InvalidSubnetID.NotFound",)
        )
    )
    return vpc_id, subnet_id


def _subnet_ids_of(group):
    return sorted(s["SubnetIdentifier"] for s in group.get("Subnets", []))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCacheSubnetGroup REPLACES the subnet list; mixing VPCs in one request is refused with
    InvalidSubnet (a nonexistent subnet gets InvalidParameterValue) and leaves the group unchanged,
    while a whole-list move to another VPC is accepted and moves VpcId.

    Reference: https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_ModifyCacheSubnetGroup.html"""
    ec = ctx.client("elasticache")
    ec2 = ctx.client("ec2")

    subnet_a, subnet_b, subnet_c = _default_subnets_by_az(ec2, 3, ctx=ctx)

    # ---- valid setup ---------------------------------------------------------------
    name = ctx.unique_name("sim2real-behav-ecsg-replace-")
    created = ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real replace-semantics check",
        SubnetIds=[subnet_a, subnet_b],
    )["CacheSubnetGroup"]
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, name))
    default_vpc = created.get("VpcId")
    assert default_vpc, f"CreateCacheSubnetGroup returned no VpcId: {created}"
    assert _subnet_ids_of(created) == sorted([subnet_a, subnet_b]), (
        f"create echoed {_subnet_ids_of(created)}, expected "
        f"{sorted([subnet_a, subnet_b])}"
    )

    # ---- positive: modify REPLACES the list, it does not merge ---------------------
    ec.modify_cache_subnet_group(
        CacheSubnetGroupName=name,
        SubnetIds=[subnet_b, subnet_c],
    )
    replaced = _describe_subnet_group(ec, name)
    assert replaced is not None, f"{name} vanished after ModifyCacheSubnetGroup"
    got = _subnet_ids_of(replaced)
    assert got == sorted([subnet_b, subnet_c]), (
        f"ModifyCacheSubnetGroup must REPLACE the subnet list, not merge it: group now "
        f"holds {got}, expected exactly {sorted([subnet_b, subnet_c])}"
    )
    assert subnet_a not in got, (
        f"MERGE BUG: subnet {subnet_a} was removed from the request but is still a member "
        f"of {name} ({got})"
    )
    good_membership = got

    # ---- break exactly one thing: a real subnet in a different VPC -----------------
    foreign_vpc, foreign_subnet = _make_foreign_vpc(ec2, ctx)
    assert foreign_vpc != default_vpc, (
        f"the throwaway VPC {foreign_vpc} must differ from the run's shared network {default_vpc}"
    )

    _code, message = _assert_error(
        lambda: ec.modify_cache_subnet_group(
            CacheSubnetGroupName=name,
            SubnetIds=[subnet_b, foreign_subnet],
        ),
        "InvalidSubnet",
        f"ModifyCacheSubnetGroup mixing VPC {default_vpc} and VPC {foreign_vpc}",
    )
    ab = f"Subnets {subnet_b} and {foreign_subnet} are not in the same VPC."
    ba = f"Subnets {foreign_subnet} and {subnet_b} are not in the same VPC."
    # AWS names the two subnets in either order.
    assert message == (ab if message.startswith(f"Subnets {subnet_b} ") else ba), (
        f"ModifyCacheSubnetGroup mixing VPC {default_vpc} and VPC {foreign_vpc}: "
        f"expected {ab!r} or {ba!r}, got {message!r}"
    )

    # ---- effect absent -------------------------------------------------------------
    after = _describe_subnet_group(ec, name)
    assert after is not None, "subnet group vanished after a rejected modify"
    assert _subnet_ids_of(after) == good_membership, (
        f"REJECTED cross-VPC modify still mutated membership: group now holds "
        f"{_subnet_ids_of(after)}, expected {good_membership}"
    )
    assert after.get("VpcId") == default_vpc, (
        f"REJECTED cross-VPC modify changed the group's VpcId from {default_vpc} to "
        f"{after.get('VpcId')}"
    )

    # ---- break exactly one thing on the create path too ----------------------------
    cross_name = ctx.unique_name("sim2real-behav-ecsg-crossvpc-")
    _code, create_message = _assert_error(
        lambda: ec.create_cache_subnet_group(
            CacheSubnetGroupName=cross_name,
            CacheSubnetGroupDescription="sim2real cross-vpc must be refused",
            SubnetIds=[subnet_b, foreign_subnet],
        ),
        "InvalidSubnet",
        f"CreateCacheSubnetGroup spanning VPC {default_vpc} and VPC {foreign_vpc}",
    )
    ab = f"Subnets {subnet_b} and {foreign_subnet} are not in the same VPC."
    ba = f"Subnets {foreign_subnet} and {subnet_b} are not in the same VPC."
    # AWS names the two subnets in either order.
    assert create_message == (ab if create_message.startswith(f"Subnets {subnet_b} ") else ba), (
        f"CreateCacheSubnetGroup spanning VPC {default_vpc} and VPC {foreign_vpc}: "
        f"expected {ab!r} or {ba!r}, got {create_message!r}"
    )
    assert _describe_subnet_group(ec, cross_name) is None, (
        f"REJECTED cross-VPC create still materialised the group {cross_name}"
    )

    # ---- a DIFFERENT bad subnet must get a DIFFERENT code --------------------------
    # A subnet id that does not exist at all is a weaker defect than one that exists in the
    # wrong VPC, and ElastiCache reports them with different codes.
    absent_name = ctx.unique_name("sim2real-behav-ecsg-absent-")
    absent_subnet = "subnet-0123456789abcdef0"
    assert absent_subnet not in (subnet_a, subnet_b, subnet_c, foreign_subnet), (
        f"fixed placeholder id {absent_subnet} collided with a real subnet from this account"
    )
    _absent_code, absent_message = _assert_error(
        lambda: ec.create_cache_subnet_group(
            CacheSubnetGroupName=absent_name,
            CacheSubnetGroupDescription="sim2real nonexistent subnet must be refused",
            SubnetIds=[subnet_b, absent_subnet],
        ),
        "InvalidParameterValueException",
        f"CreateCacheSubnetGroup naming the nonexistent subnet {absent_subnet}",
    )
    assert _fault_base(_absent_code) != "InvalidSubnet", (
        "a subnet id that does not exist must NOT be reported with the same code as a subnet "
        f"that exists in the wrong VPC; both came back as {_absent_code}"
    )
    ab = f"Some input subnets in :[{subnet_b}, {absent_subnet}] are invalid."
    ba = f"Some input subnets in :[{absent_subnet}, {subnet_b}] are invalid."
    # AWS lists the two input subnets in either order.
    assert absent_message == (ab if absent_message.startswith(f"Some input subnets in :[{subnet_b},") else ba), (
        f"the nonexistent-subnet refusal: expected {ab!r} or {ba!r}, got {absent_message!r}"
    )
    assert _describe_subnet_group(ec, absent_name) is None, (
        f"REJECTED nonexistent-subnet create still materialised the group {absent_name}"
    )

    # ---- the ACCEPTANCE boundary: a WHOLE-list move to another VPC is allowed --------
    # ElastiCache validates only that the subnets in one request agree with EACH OTHER, not
    # that the group keeps the VPC it was created in. Replacing the entire list with the
    # foreign subnet is accepted and the group's VpcId follows the subnets. This is asserted
    # so the refusals above are pinned to "mixing", not to "the foreign VPC is forbidden".
    moved = ec.modify_cache_subnet_group(
        CacheSubnetGroupName=name,
        SubnetIds=[foreign_subnet],
    )["CacheSubnetGroup"]
    assert _subnet_ids_of(moved) == [foreign_subnet], (
        f"a whole-list replacement into another VPC must be accepted verbatim; group holds "
        f"{_subnet_ids_of(moved)}"
    )
    assert moved.get("VpcId") == foreign_vpc, (
        f"a cache subnet group's VpcId is DERIVED from its subnets, so moving every subnet "
        f"moves the group: expected {foreign_vpc}, got {moved.get('VpcId')}"
    )
    persisted = _describe_subnet_group(ec, name)
    assert persisted is not None and persisted.get("VpcId") == foreign_vpc, (
        f"the VPC move must persist to DescribeCacheSubnetGroups, got "
        f"{persisted and persisted.get('VpcId')}"
    )
    # ...and the mixing rule is SYMMETRIC: from the foreign VPC, adding a default-VPC subnet
    # is refused with the same code, so the refusal is about disagreement and not about which
    # VPC is "home".
    _sym_code, sym_message = _assert_error(
        lambda: ec.modify_cache_subnet_group(
            CacheSubnetGroupName=name,
            SubnetIds=[foreign_subnet, subnet_a],
        ),
        "InvalidSubnet",
        f"ModifyCacheSubnetGroup mixing FROM VPC {foreign_vpc} back into {default_vpc}",
    )
    ab = f"Subnets {foreign_subnet} and {subnet_a} are not in the same VPC."
    ba = f"Subnets {subnet_a} and {foreign_subnet} are not in the same VPC."
    # AWS names the two subnets in either order.
    assert sym_message == (ab if sym_message.startswith(f"Subnets {foreign_subnet} ") else ba), (
        f"ModifyCacheSubnetGroup mixing FROM VPC {foreign_vpc} back into {default_vpc}: "
        f"expected {ab!r} or {ba!r}, got {sym_message!r}"
    )
    still_foreign = _describe_subnet_group(ec, name)
    assert still_foreign is not None and _subnet_ids_of(still_foreign) == [foreign_subnet], (
        f"the symmetric rejection mutated membership: group holds "
        f"{still_foreign and _subnet_ids_of(still_foreign)}"
    )

    # ---- control case still works ---------------------------------------------------
    ec.modify_cache_subnet_group(
        CacheSubnetGroupName=name,
        SubnetIds=[subnet_a, subnet_b, subnet_c],
    )
    final = _describe_subnet_group(ec, name)
    assert final is not None and _subnet_ids_of(final) == sorted(
        [subnet_a, subnet_b, subnet_c]
    ), (
        f"control case failed: after the rejections a legal replacement no longer applies; "
        f"group holds {final and _subnet_ids_of(final)}"
    )
    assert final.get("VpcId") == default_vpc, (
        f"the group must follow its subnets back to {default_vpc}, got {final.get('VpcId')}"
    )

    _delete_subnet_group(ec, name)
    assert _describe_subnet_group(ec, name) is None, (
        f"{name} still describable after DeleteCacheSubnetGroup"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
