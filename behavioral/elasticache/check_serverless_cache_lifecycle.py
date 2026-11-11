"""serverless-cache-lifecycle."""
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
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError but the call SUCCEEDED")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, got = _error(fn)
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code}"
    assert got == expected[1], f"expected message {expected[1]!r}, got {got!r}"
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

def _poll(probe, predicate, timeout_s=600, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)

def _wait_status(fn, list_key, id_field, id_value, status_field, target, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is not None and item.get(status_field) == target,
        timeout_s, interval_s,
    )

def _wait_deleted(fn, list_key, id_field, id_value, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is None,
        timeout_s, interval_s,
    )

def _describe_serverless_cache(ec, name):
    return _describe_one(ec.describe_serverless_caches, "ServerlessCaches", "ServerlessCacheName", name)

def _wait_serverless_status(ec, name, status, timeout_s=1200, interval_s=15):
    return _wait_status(ec.describe_serverless_caches, "ServerlessCaches", "ServerlessCacheName", name, "Status", status, timeout_s, interval_s)

def _wait_serverless_deleted(ec, name, timeout_s=1200, interval_s=15):
    return _wait_deleted(ec.describe_serverless_caches, "ServerlessCaches", "ServerlessCacheName", name, timeout_s, interval_s)

def _delete_serverless_if_present(ec, name):
    """Cleanup: delete the cache unless the check already deleted it."""
    try:
        ec.delete_serverless_cache(ServerlessCacheName=name)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ServerlessCacheNotFoundFault":
            raise

CHECK = "serverless-cache-lifecycle"
GROUP = 'serverless'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A serverless cache becomes available with engine redis, an endpoint and an ARN, refuses a duplicate name with its
    exact message, applies a Description change and reports deleting on delete; once gone, Describe and Modify fail
    with ServerlessCacheNotFound "Serverless cache with name <name> not found."."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-esc-")
    created = ec.create_serverless_cache(
        ServerlessCacheName=name,
        Engine="redis",
        Description="fidelity check serverless",
        SubnetIds=ctx.network().subnet_ids[:3],
    )["ServerlessCache"]
    ctx.on_cleanup(lambda: _delete_serverless_if_present(ec, name))
    assert created["ServerlessCacheName"] == name, f"expected {name!r}, got {created['ServerlessCacheName']!r}"
    assert created["Status"] in ("creating", "available"), created["Status"]

    cache = _wait_serverless_status(ec, name, "available", timeout_s=1200)
    assert cache is not None, "serverless cache never reached available"
    assert cache["Engine"].lower() == "redis", cache
    assert cache.get("Endpoint", {}).get("Address"), cache
    assert cache.get("ARN"), cache

    # Duplicate name is refused while the original exists.
    _assert_error(lambda: ec.create_serverless_cache(
        ServerlessCacheName=name, Engine="redis",
        SubnetIds=ctx.network().subnet_ids[:3],
    ), ("ServerlessCacheAlreadyExistsFault", "Serverless Cache already exists"))

    new_desc = "fidelity check serverless modified"
    ec.modify_serverless_cache(ServerlessCacheName=name, Description=new_desc)
    _poll(
        lambda: _describe_serverless_cache(ec, name),
        lambda c: c is not None and c.get("Description") == new_desc,
        600, 15,
    )

    ec.delete_serverless_cache(ServerlessCacheName=name)
    deleting = _describe_serverless_cache(ec, name)
    assert deleting is not None and deleting["Status"] == "deleting", deleting
    _wait_serverless_deleted(ec, name, timeout_s=900)

    # Gone: an independent read returns the specific not-found code, and a
    # mutation on the dead id fails the same way rather than silently no-op'ing.
    not_found = f"Serverless cache with name {name} not found."
    _assert_error(
        lambda: ec.describe_serverless_caches(ServerlessCacheName=name),
        ("ServerlessCacheNotFoundFault", not_found),
    )
    _assert_error(
        lambda: ec.modify_serverless_cache(ServerlessCacheName=name, Description="post-delete"),
        ("ServerlessCacheNotFoundFault", not_found),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
