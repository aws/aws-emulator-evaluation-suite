"""create-cache-cluster-invalid-arguments."""
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

def _assert_never_provisioned(ec, cluster_id):
    """Effect-absent, via an independent read: no cluster with this id exists."""
    code, message = _error(lambda: ec.describe_cache_clusters(CacheClusterId=cluster_id))
    assert code == "CacheClusterNotFound", (
        f"expected {cluster_id} to have never been provisioned (CacheClusterNotFound), got {code}"
    )
    expected = f"CacheCluster not found: {cluster_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

def _wait_available(ec, cluster_id, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = ec.describe_cache_clusters(CacheClusterId=cluster_id)
        clusters = resp.get("CacheClusters", [])
        if clusters:
            status = clusters[0]["CacheClusterStatus"]
            if status == "available":
                return status
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never became available, last status={status}")

_BAD_ID_MESSAGE = (
    "The parameter CacheClusterIdentifier is not a valid identifier. Identifiers must begin "
    "with a letter; must contain only ASCII letters, digits, and hyphens; and must not end "
    "with a hyphen or contain two consecutive hyphens."
)

CHECK = "create-cache-cluster-invalid-arguments"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A malformed CacheClusterId (in CreateCacheCluster and DescribeCacheClusters), an unknown node type and an
    unknown engine are each refused with InvalidParameterValue and its exact message and provision nothing, while
    a well-formed CreateCacheCluster on the same subnet group becomes available."""
    ec = ctx.client("elasticache")

    # Positive control: proves CreateCacheCluster works in this account/credentials, so the
    # rejections below cannot be "this account can't create clusters at all" in disguise.
    good_id = ctx.unique_name("sim2real-behav-ecc-ok-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=good_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: ec.delete_cache_cluster(CacheClusterId=good_id))
    status = _wait_available(ec, good_id)
    assert status == "available", f"positive-control cluster never became available: {status}"

    # Underscores/uppercase are not legal in a CacheClusterId.
    bad_id = "Sim2Real_Behav_Bad_Id"
    _assert_error(lambda: ec.create_cache_cluster(
        CacheClusterId=bad_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
    ), ("InvalidParameterValueException", _BAD_ID_MESSAGE))
    # Independent read: DescribeCacheClusters enforces the same id-format rule (it rejects the
    # malformed id rather than answering CacheClusterNotFound), so no cluster can carry this id.
    _assert_error(
        lambda: ec.describe_cache_clusters(CacheClusterId=bad_id),
        ("InvalidParameterValueException",
        _BAD_ID_MESSAGE),
    )

    # A node type that does not exist must not provision anything.
    badtype_id = ctx.unique_name("sim2real-behav-ecc-badtype-")
    _assert_error(lambda: ec.create_cache_cluster(
        CacheClusterId=badtype_id,
        Engine="redis",
        CacheNodeType="cache.bogus.xlarge",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
    ), ("InvalidParameterValueException", "Invalid Cache Node Type: cache.bogus.xlarge."))
    _assert_never_provisioned(ec, badtype_id)

    # An engine that does not exist must not provision anything.
    badengine_id = ctx.unique_name("sim2real-behav-ecc-badengine-")
    _assert_error(lambda: ec.create_cache_cluster(
        CacheClusterId=badengine_id,
        Engine="not-an-engine",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
    ), ("InvalidParameterValueException", "Invalid Cache engine: not-an-engine."))
    _assert_never_provisioned(ec, badengine_id)


def _network_cache_subnet_group(ctx, client) -> str:
    """An ElastiCache subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-csg-")
    client.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cache_subnet_group(CacheSubnetGroupName=name),
            # DeleteCacheSubnetGroup refuses a group a cluster still holds with CacheSubnetGroupInUse.
            ("CacheSubnetGroupInUse", "InvalidCacheSubnetGroupState"),
            ("CacheSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
