"""cache-parameter-group-lifecycle."""
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

def _refusal(fn):
    """(code without its modeled Fault/Exception suffix, message) of the error fn() raises."""
    code, message = _error(fn)
    return _fault_base(code), message

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

CHECK = "cache-parameter-group-lifecycle"
GROUP = 'parameter-group'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cache parameter group is created and described; a duplicate-name create fails with
    CacheParameterGroupAlreadyExists and its exact message, leaving the original intact; after deletion the
    name is not found, and the same create then succeeds."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-ecpg-")
    created = ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="fidelity check parameter group",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["CacheParameterGroup"]
    ctx.on_cleanup(lambda: _delete_parameter_group_when_ready(ec, name, timeout_s=60))
    assert created["CacheParameterGroupName"] == name, created
    assert created["CacheParameterGroupFamily"] == "redis7", created

    listed = ec.describe_cache_parameter_groups(CacheParameterGroupName=name)
    assert len(listed["CacheParameterGroups"]) == 1, listed
    group = listed["CacheParameterGroups"][0]
    assert group["CacheParameterGroupFamily"] == "redis7", group

    # Duplicate name is rejected, and the rejected attempt leaves the original untouched.
    refused = _refusal(
        lambda: ec.create_cache_parameter_group(
            CacheParameterGroupName=name,
            CacheParameterGroupFamily="redis7",
            Description="dup",
        ),
    )
    assert refused == (
        "CacheParameterGroupAlreadyExists",
        f"Parameter group {name} already exists",
    ), f"expected CacheParameterGroupAlreadyExists with its exact message, got {refused!r}"
    unchanged = _describe_parameter_group(ec, name)
    assert unchanged is not None, "original group vanished after a rejected duplicate create"
    assert unchanged["Description"] == "fidelity check parameter group", (
        f"rejected duplicate create mutated the original group's description: {unchanged}"
    )

    # Restore: delete the original, the actual source of the name conflict.
    ec.delete_cache_parameter_group(CacheParameterGroupName=name)
    assert _describe_parameter_group(ec, name) is None, "group still visible right after delete"
    refused = _refusal(lambda: ec.delete_cache_parameter_group(CacheParameterGroupName=name))
    assert refused == (
        "CacheParameterGroupNotFound",
        f"CacheParameterGroupnot found: {name}",
    ), f"expected CacheParameterGroupNotFound with its exact message, got {refused!r}"

    # The identical create that was rejected above now succeeds: the name was only
    # unavailable while the original held it, never unusable outright.
    recreated = ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="fidelity check parameter group (recreated)",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["CacheParameterGroup"]
    assert recreated["CacheParameterGroupName"] == name, recreated
    assert recreated["CacheParameterGroupFamily"] == "redis7", recreated

    final = ec.describe_cache_parameter_groups(CacheParameterGroupName=name)["CacheParameterGroups"]
    assert len(final) == 1, final
    assert final[0]["Description"] == "fidelity check parameter group (recreated)", final[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
