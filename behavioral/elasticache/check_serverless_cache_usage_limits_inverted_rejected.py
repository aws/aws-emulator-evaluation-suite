"""serverless-cache-usage-limits-inverted-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "serverless-cache-usage-limits-inverted-rejected"
GROUP = 'serverless'
SERVICES = ['elasticache']

_ENGINE = "valkey"
# The cheapest shape that still has usage limits: a serverless cache has no always-on node,
# and a 1 GiB floor with a small ECPU ceiling is the smallest configurable envelope.
_GOOD = {
    "DataStorage": {"Minimum": 1, "Maximum": 10, "Unit": "GB"},
    "ECPUPerSecond": {"Minimum": 1000, "Maximum": 5000},
}
_WIDER = {
    "DataStorage": {"Minimum": 1, "Maximum": 20, "Unit": "GB"},
    "ECPUPerSecond": {"Minimum": 1000, "Maximum": 9000},
}

_STORAGE_INVERTED = "Invalid values for DataStorage. Minimum must not be greater than Maximum."
_ECPU_INVERTED = "Invalid values for ECPUPerSecond. Minimum must not be greater than Maximum."


def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _error(fn, what):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what}: expected a ClientError but the call SUCCEEDED (over-permissive)")


def _assert_error(fn, expected, message, what):
    """Assert fn() fails with `expected` (Fault/Exception-suffix normalized) and exactly `message`."""
    code, got = _error(fn, what)
    assert _fault_base(code) == _fault_base(expected), (
        f"{what}: expected {expected}, got {code}"
    )
    assert got == message, f"{what}: expected message {message!r}, got {got!r}"
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


def _poll(probe, predicate, timeout_s=900, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _describe_serverless(ec, name):
    return _describe_one(ec.describe_serverless_caches, "ServerlessCaches", "ServerlessCacheName", name)


def _delete_serverless_and_wait(ec, name, timeout_s=900, interval_s=15):
    """Delete a serverless cache with no final snapshot and poll it to actual disappearance.

    A cache still `creating` cannot be deleted, so this retries through InvalidServerlessCacheState.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_serverless_cache(ServerlessCacheName=name)
            break
        except ClientError as e:
            code = _fault_base(e.response.get("Error", {}).get("Code") or "")
            if code == "ServerlessCacheNotFound":
                return
            if code != "InvalidServerlessCacheState" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    _poll(lambda: _describe_serverless(ec, name), lambda c: c is None,
          timeout_s=timeout_s, interval_s=interval_s)


def _limits(cache):
    return (cache or {}).get("CacheUsageLimits") or {}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CacheUsageLimits with Minimum > Maximum are refused on create and on modify.
    A refused ModifyServerlessCache leaves the live limits unchanged; a legal widening applies.

    Reference: https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CacheUsageLimits.html
    """
    ec = ctx.client("elasticache")

    # ---- break the create path first: nothing gets provisioned, so this is free ------
    inverted_storage_name = ctx.unique_name("sim2real-behav-ecsl-ist-")
    _assert_error(
        lambda: ec.create_serverless_cache(
            ServerlessCacheName=inverted_storage_name,
            Engine=_ENGINE,
            CacheUsageLimits={
                "DataStorage": {"Minimum": 50, "Maximum": 10, "Unit": "GB"},
                "ECPUPerSecond": {"Minimum": 1000, "Maximum": 5000},
            },
            SubnetIds=ctx.network().subnet_ids[:3],
        ),
        "InvalidParameterValueException",
        _STORAGE_INVERTED,
        "CreateServerlessCache with DataStorage Minimum=50 > Maximum=10",
    )
    assert _describe_serverless(ec, inverted_storage_name) is None, (
        f"REJECTED CreateServerlessCache still materialised {inverted_storage_name}"
    )

    inverted_ecpu_name = ctx.unique_name("sim2real-behav-ecsl-iec-")
    _assert_error(
        lambda: ec.create_serverless_cache(
            ServerlessCacheName=inverted_ecpu_name,
            Engine=_ENGINE,
            CacheUsageLimits={
                "DataStorage": {"Minimum": 1, "Maximum": 10, "Unit": "GB"},
                "ECPUPerSecond": {"Minimum": 9000, "Maximum": 1000},
            },
            SubnetIds=ctx.network().subnet_ids[:3],
        ),
        "InvalidParameterValueException",
        _ECPU_INVERTED,
        "CreateServerlessCache with ECPUPerSecond Minimum=9000 > Maximum=1000",
    )
    assert _describe_serverless(ec, inverted_ecpu_name) is None, (
        f"REJECTED CreateServerlessCache still materialised {inverted_ecpu_name}"
    )

    # ---- full valid setup ------------------------------------------------------------
    name = ctx.unique_name("sim2real-behav-ecsl-limits-")
    created = ec.create_serverless_cache(
        ServerlessCacheName=name,
        Engine=_ENGINE,
        Description="sim2real serverless usage-limit check",
        CacheUsageLimits=_GOOD,
        SnapshotRetentionLimit=0,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:check", "Value": CHECK},
        ],
        SubnetIds=ctx.network().subnet_ids[:3],
    )["ServerlessCache"]
    # Registered immediately, BEFORE the id is used for anything else, so a failure between
    # here and the first assert cannot leak a billable cache.
    ctx.on_cleanup(lambda: _delete_serverless_and_wait(ec, name))
    assert created["ServerlessCacheName"] == name, created
    assert created.get("Status") == "creating", (
        f"the create response must report the transitional state, got "
        f"{created.get('Status')!r}"
    )

    # Provisioning takes minutes; the 900 s default deadline is headroom.
    cache = _poll(
        lambda: _describe_serverless(ec, name),
        lambda c: c is not None and c.get("Status") == "available",
        timeout_s=900,
    )
    got = _limits(cache)
    assert got.get("DataStorage", {}).get("Minimum") == 1, got
    assert got.get("DataStorage", {}).get("Maximum") == 10, got
    assert got.get("DataStorage", {}).get("Unit") == "GB", got
    assert got.get("ECPUPerSecond", {}).get("Minimum") == 1000, got
    assert got.get("ECPUPerSecond", {}).get("Maximum") == 5000, got
    baseline = {
        "DataStorage": dict(got["DataStorage"]),
        "ECPUPerSecond": dict(got["ECPUPerSecond"]),
    }

    # ---- break exactly one thing on a LIVE cache -----------------------------------
    _assert_error(
        lambda: ec.modify_serverless_cache(
            ServerlessCacheName=name,
            CacheUsageLimits={"ECPUPerSecond": {"Minimum": 9000, "Maximum": 1000}},
        ),
        "InvalidParameterValueException",
        _ECPU_INVERTED,
        "ModifyServerlessCache with ECPUPerSecond Minimum=9000 > Maximum=1000",
    )

    # ---- effect absent --------------------------------------------------------------
    after = _describe_serverless(ec, name)
    assert after is not None, "serverless cache vanished after a rejected modify"
    after_limits = _limits(after)
    assert after_limits.get("ECPUPerSecond") == baseline["ECPUPerSecond"], (
        f"REJECTED ModifyServerlessCache still mutated the live cache: ECPUPerSecond is now "
        f"{after_limits.get('ECPUPerSecond')}, expected {baseline['ECPUPerSecond']}"
    )
    assert after_limits.get("DataStorage") == baseline["DataStorage"], (
        f"REJECTED ModifyServerlessCache also mutated DataStorage: now "
        f"{after_limits.get('DataStorage')}, expected {baseline['DataStorage']}"
    )
    assert after.get("Status") == "available", (
        f"a rejected modify must leave the cache available, got {after.get('Status')!r}"
    )

    # ---- control case still works ---------------------------------------------------
    ec.modify_serverless_cache(ServerlessCacheName=name, CacheUsageLimits=_WIDER)
    widened = _poll(
        lambda: _describe_serverless(ec, name),
        lambda c: (
            c is not None
            and _limits(c).get("ECPUPerSecond", {}).get("Maximum") == 9000
            and c.get("Status") == "available"
        ),
        timeout_s=900,
    )
    assert _limits(widened).get("DataStorage", {}).get("Maximum") == 20, (
        f"control case failed: the legal widening did not apply DataStorage.Maximum=20; "
        f"limits are {_limits(widened)}"
    )

    _delete_serverless_and_wait(ec, name)
    assert _describe_serverless(ec, name) is None, f"{name} still resolves after delete"
    not_found = f"Serverless cache with name {name} not found."
    _assert_error(
        lambda: ec.describe_serverless_caches(ServerlessCacheName=name),
        "ServerlessCacheNotFoundFault", not_found,
        "DescribeServerlessCaches after delete",
    )
    _assert_error(
        lambda: ec.modify_serverless_cache(ServerlessCacheName=name, CacheUsageLimits=_GOOD),
        "ServerlessCacheNotFoundFault", not_found,
        "ModifyServerlessCache on a deleted cache",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
