"""concurrent-duplicate-parameter-group."""
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

def _run_calls(fn, n):
    """Invoke fn() n times concurrently; return [(ok, value_or_(code, message))]."""
    import concurrent.futures
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(fn) for _ in range(n)]
        for f in concurrent.futures.as_completed(futures):
            try:
                out.append((True, f.result()))
            except ClientError as e:
                error = e.response.get("Error", {})
                out.append((False, (error.get("Code"), error.get("Message"))))
            except Exception as e:
                out.append((False, repr(e)))
    return out

def _describe_parameter_group(ec, name):
    return _describe_one(ec.describe_cache_parameter_groups, "CacheParameterGroups", "CacheParameterGroupName", name)

def _delete_parameter_group_when_ready(ec, name, timeout_s=300, interval_s=10):
    """Delete a cache parameter group, retrying while it is still applying (InvalidState)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_parameter_group(CacheParameterGroupName=name)
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code") or ""
            if "NotFound" in code:
                return
            if _fault_base(code) != "InvalidCacheParameterGroupState":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

CHECK = "concurrent-duplicate-parameter-group"
GROUP = 'concurrency'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateCacheParameterGroup on one name: exactly one wins, others get AlreadyExists."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-ecpg-race-")
    ctx.on_cleanup(lambda: _delete_parameter_group_when_ready(ec, name, timeout_s=60))

    def attempt():
        return ec.create_cache_parameter_group(
            CacheParameterGroupName=name,
            CacheParameterGroupFamily="redis7",
            Description="fidelity check concurrent create",
        )

    results = _run_calls(attempt, 4)
    successes = [value for ok, value in results if ok]
    failures = [value for ok, value in results if not ok]
    assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)}: {results}"
    expected_message = f"Parameter group {name} already exists"
    for failure in failures:
        assert failure == ("CacheParameterGroupAlreadyExists", expected_message), failures

    assert _describe_parameter_group(ec, name) is not None, (
        f"expected {name} to be describable after the winning create"
    )

    ec.delete_cache_parameter_group(CacheParameterGroupName=name)
    assert _describe_parameter_group(ec, name) is None, (
        f"expected {name} to be gone after delete, describe still returned it"
    )
    try:
        ec.delete_cache_parameter_group(CacheParameterGroupName=name)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        message = e.response.get("Error", {}).get("Message")
        assert _fault_base(code) == "CacheParameterGroupNotFound", (
            f"expected CacheParameterGroupNotFoundFault on double-delete, got {code}"
        )
        expected_nf = f"CacheParameterGroupnot found: {name}"
        assert message == expected_nf, f"expected message {expected_nf!r}, got {message!r}"
    else:
        raise AssertionError(
            f"expected double-delete of {name} to fail with NotFound, but it SUCCEEDED"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
