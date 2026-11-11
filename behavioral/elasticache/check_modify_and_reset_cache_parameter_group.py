"""modify-and-reset-cache-parameter-group."""
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

CHECK = "modify-and-reset-cache-parameter-group"
GROUP = 'parameter-group'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCacheParameterGroup sets maxmemory-policy and ResetCacheParameterGroup restores the redis7 engine default;
    a non-modifiable parameter is refused with InvalidParameterValue "The parameter <name> cannot be modified.", and
    after deletion a modify fails with CacheParameterGroupNotFound and its exact message."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-ecpg-mod-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="fidelity check modify/reset",
        Tags=[{"Key": "sim2real-purpose", "Value": "modify-and-reset-cache-parameter-group"}],
    )
    ctx.on_cleanup(lambda: _delete_parameter_group_when_ready(ec, name, timeout_s=60))

    default_params = ec.describe_engine_default_parameters(
        CacheParameterGroupFamily="redis7",
    )["EngineDefaults"]["Parameters"]
    target = next(
        p for p in default_params
        if p.get("IsModifiable") and p.get("ParameterName") == "maxmemory-policy"
    )
    default_value = target.get("ParameterValue") or "volatile-lru"
    new_value = "allkeys-lru" if default_value != "allkeys-lru" else "allkeys-lfu"

    # A brand-new group starts at the family default.
    params_initial = ec.describe_cache_parameters(CacheParameterGroupName=name)["Parameters"]
    initial = next(p for p in params_initial if p["ParameterName"] == "maxmemory-policy")
    assert initial["ParameterValue"] == default_value, initial

    ec.modify_cache_parameter_group(
        CacheParameterGroupName=name,
        ParameterNameValues=[{"ParameterName": "maxmemory-policy", "ParameterValue": new_value}],
    )
    params = ec.describe_cache_parameters(CacheParameterGroupName=name)["Parameters"]
    modified = next(p for p in params if p["ParameterName"] == "maxmemory-policy")
    assert modified["ParameterValue"] == new_value, modified

    # A non-modifiable parameter must be rejected rather than silently accepted.
    non_modifiable = next(
        (p["ParameterName"] for p in default_params if p.get("IsModifiable") is False),
        None,
    )
    assert non_modifiable is not None, "expected at least one non-modifiable parameter in redis7 engine defaults"
    _assert_error(lambda: ec.modify_cache_parameter_group(
        CacheParameterGroupName=name,
        ParameterNameValues=[
            {"ParameterName": non_modifiable, "ParameterValue": "1"},
        ],
    ), ("InvalidParameterValueException", f"The parameter {non_modifiable} cannot be modified."))

    ec.reset_cache_parameter_group(
        CacheParameterGroupName=name,
        ParameterNameValues=[{"ParameterName": "maxmemory-policy", "ParameterValue": ""}],
    )
    params_after = ec.describe_cache_parameters(CacheParameterGroupName=name)["Parameters"]
    reset_param = next(p for p in params_after if p["ParameterName"] == "maxmemory-policy")
    assert reset_param["ParameterValue"] == default_value, reset_param

    _delete_parameter_group_when_ready(ec, name)
    assert _describe_parameter_group(ec, name) is None, f"{name} still present after delete"
    _assert_error(
        lambda: ec.modify_cache_parameter_group(
            CacheParameterGroupName=name,
            ParameterNameValues=[{"ParameterName": "maxmemory-policy", "ParameterValue": new_value}],
        ),
        ("CacheParameterGroupNotFoundFault",
        f"CacheParameterGroup not found: {name}"),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
