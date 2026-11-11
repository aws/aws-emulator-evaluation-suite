"""parameter-group-not-found-semantics."""
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
    """Call fn(); return (code, message) from the ClientError it must raise.

    An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, message = _error(fn)
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code}"
    assert message == expected[1], f"expected message {expected[1]!r}, got {message!r}"
    return code

def _assert_succeeds(fn, desc):
    """Call fn(); raise with expected-vs-actual if it fails. The positive control's counterpart
    to `_assert_error` — proves the NotFound rejection is tied to the group's absence, not to a
    target that refuses every call regardless of validity."""
    try:
        return fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(f"expected {desc} to succeed against a REAL group, got {code}") from exc

def _delete_parameter_group_when_ready(ec, name, timeout_s=60, interval_s=5):
    """Delete a cache parameter group, retrying while it is still applying (InvalidCacheParameterGroupState)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_parameter_group(CacheParameterGroupName=name)
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code") or ""
            if "NotFound" in code:
                return
            if _fault_base(code) != "InvalidCacheParameterGroupState" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

CHECK = "parameter-group-not-found-semantics"
GROUP = 'parameter-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Parameter reads/writes against an unknown group raise CacheParameterGroupNotFound; the
    identical calls succeed against a real, freshly-created group, so the rejection is proven to
    be about the group's absence and not a target that refuses every call unconditionally."""
    ec = ctx.client("elasticache")

    # Positive control: the same three parameter-group operations succeed against a real group.
    real_name = ctx.unique_name("sim2real-behav-ecpg-real-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=real_name,
        CacheParameterGroupFamily="redis7",
        Description="fidelity check not-found positive control",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_parameter_group_when_ready(ec, real_name))

    _assert_succeeds(
        lambda: ec.describe_cache_parameters(CacheParameterGroupName=real_name),
        "describe_cache_parameters",
    )
    _assert_succeeds(
        lambda: ec.modify_cache_parameter_group(
            CacheParameterGroupName=real_name,
            ParameterNameValues=[
                {"ParameterName": "maxmemory-policy", "ParameterValue": "allkeys-lru"},
            ],
        ),
        "modify_cache_parameter_group",
    )
    _assert_succeeds(
        lambda: ec.reset_cache_parameter_group(
            CacheParameterGroupName=real_name, ResetAllParameters=True,
        ),
        "reset_cache_parameter_group",
    )

    bogus = ctx.unique_name("sim2real-behav-ecpg-missing-")
    _assert_error(
        lambda: ec.describe_cache_parameters(CacheParameterGroupName=bogus),
        ("CacheParameterGroupNotFoundFault",
        f"CacheParameterGroupnot found: {bogus}"),
    )
    _assert_error(
        lambda: ec.modify_cache_parameter_group(
            CacheParameterGroupName=bogus,
            ParameterNameValues=[
                {"ParameterName": "maxmemory-policy", "ParameterValue": "allkeys-lru"},
            ],
        ),
        ("CacheParameterGroupNotFoundFault",
        f"CacheParameterGroup not found: {bogus}"),
    )
    _assert_error(
        lambda: ec.reset_cache_parameter_group(
            CacheParameterGroupName=bogus, ResetAllParameters=True,
        ),
        ("CacheParameterGroupNotFoundFault",
        f"CacheParameterGroupnot found: {bogus}"),
    )
    # A cluster cannot be created against a parameter group that does not exist.
    subnet_group = _network_cache_subnet_group(ctx, ec)
    _assert_error(lambda: ec.create_cache_cluster(
        CacheClusterId=ctx.unique_name("sim2real-behav-ecc-badpg-"),
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheParameterGroupName=bogus,
        CacheSubnetGroupName=subnet_group,
    ), ("CacheParameterGroupNotFoundFault", f"CacheParameterGroup not found: {bogus}"))


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
