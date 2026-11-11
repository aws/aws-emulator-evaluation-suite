"""cache-subnet-group-invalid-subnet."""
from __future__ import annotations

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

def _refusal(fn):
    """(code without its modeled Fault/Exception suffix, message) of the error fn() raises."""
    code, message = _error(fn)
    return _fault_base(code), message

CHECK = "cache-subnet-group-invalid-subnet"
GROUP = 'subnet-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A subnet group cannot be created from, or a cluster placed in, a subnet/group that does not exist."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-ecsg-bad-")
    refused = _refusal(
        lambda: ec.create_cache_subnet_group(
            CacheSubnetGroupName=name,
            CacheSubnetGroupDescription="fidelity check bad subnet",
            SubnetIds=["subnet-00000000deadbeef"],
        ),
    )
    assert refused == (
        "InvalidParameterValue",
        "Some input subnets in :[subnet-00000000deadbeef] are invalid.",
    ), f"expected InvalidParameterValue with its exact message, got {refused!r}"

    bogus_group = ctx.unique_name("sim2real-behav-ecsg-missing-")
    refused = _refusal(lambda: ec.describe_cache_subnet_groups(CacheSubnetGroupName=bogus_group))
    assert refused == (
        "CacheSubnetGroupNotFound",
        f"Cache subnet group {bogus_group} not found.",
    ), f"expected CacheSubnetGroupNotFound with its exact message, got {refused!r}"
    refused = _refusal(lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=bogus_group))
    assert refused == (
        "CacheSubnetGroupNotFound",
        f"Cache Subnet Group {bogus_group} does not exist.",
    ), f"expected CacheSubnetGroupNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.modify_cache_subnet_group(
            CacheSubnetGroupName=bogus_group,
            CacheSubnetGroupDescription="nope",
        ),
    )
    assert refused == (
        "CacheSubnetGroupNotFound",
        f"Cache Subnet Group {bogus_group} does not exist.",
    ), f"expected CacheSubnetGroupNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.create_cache_cluster(
            CacheClusterId=ctx.unique_name("sim2real-behav-ecc-badsg-"),
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheNodes=1,
            CacheSubnetGroupName=bogus_group,
        ),
    )
    assert refused == (
        "CacheSubnetGroupNotFound",
        f"Cache Subnet Group {bogus_group} does not exist.",
    ), f"expected CacheSubnetGroupNotFound with its exact message, got {refused!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
