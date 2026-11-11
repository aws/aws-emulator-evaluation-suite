"""delete-default-parameter-group-forbidden."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn, expected):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {expected} but the call SUCCEEDED")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, got = _error(fn, expected[0])
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code}"
    assert got == expected[1], f"{expected[0]}: expected message {expected[1]!r}, got {got!r}"
    return code

def _delete_if_present(ec, name):
    try:
        ec.delete_cache_parameter_group(CacheParameterGroupName=name)
    except ClientError as e:
        if "NotFound" not in (e.response.get("Error", {}).get("Code") or ""):
            raise

_INVALID_IDENTIFIER = (
    "The parameter CacheParameterGroupName is not a valid identifier. Identifiers must begin with "
    "a letter; must contain only ASCII letters, digits, and hyphens; and must not end with a "
    "hyphen or contain two consecutive hyphens."
)

CHECK = "delete-default-parameter-group-forbidden"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """default.redis7 is listed, but its delete is refused with InvalidParameterValue (identifier message) and its
    modify with "Cannot modify a default parameter group.", leaving it listed with maxmemory-policy unchanged,
    while a custom redis7 group is modified and deleted."""
    ec = ctx.client("elasticache")
    default_name = "default.redis7"
    # It must exist and be reported as the family default.
    listed = ec.describe_cache_parameter_groups(
        CacheParameterGroupName=default_name,
    )["CacheParameterGroups"]
    assert len(listed) == 1, listed
    assert listed[0]["CacheParameterGroupFamily"] == "redis7", listed[0]

    # Positive control: a custom group of the same family can be created, modified and deleted.
    custom_name = ctx.unique_name("sim2real-behav-ecpg-defprot-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=custom_name,
        CacheParameterGroupFamily="redis7",
        Description="behavioral positive control",
    )
    ctx.on_cleanup(lambda: _delete_if_present(ec, custom_name))

    custom_before = ec.describe_cache_parameters(CacheParameterGroupName=custom_name)["Parameters"]
    custom_baseline = next(p for p in custom_before if p["ParameterName"] == "maxmemory-policy")["ParameterValue"]
    custom_target = "noeviction" if custom_baseline != "noeviction" else "allkeys-lru"

    ec.modify_cache_parameter_group(
        CacheParameterGroupName=custom_name,
        ParameterNameValues=[
            {"ParameterName": "maxmemory-policy", "ParameterValue": custom_target},
        ],
    )
    custom_after = ec.describe_cache_parameters(CacheParameterGroupName=custom_name)["Parameters"]
    custom_modified = next(p for p in custom_after if p["ParameterName"] == "maxmemory-policy")
    assert custom_modified["ParameterValue"] == custom_target, custom_modified

    ec.delete_cache_parameter_group(CacheParameterGroupName=custom_name)
    _assert_error(lambda: ec.describe_cache_parameter_groups(
        CacheParameterGroupName=custom_name,
    ), ("CacheParameterGroupNotFound", f"CacheParameterGroup {custom_name} not found."))

    # The negative: the default group rejects the identical calls the custom group just accepted.
    # AWS refuses the delete at identifier validation: the dotted default name is not a name a
    # customer group can carry.
    _assert_error(lambda: ec.delete_cache_parameter_group(
        CacheParameterGroupName=default_name,
    ), ("InvalidParameterValueException", _INVALID_IDENTIFIER))

    # Independent read: the failed delete left the default group exactly as it was.
    still_listed = ec.describe_cache_parameter_groups(
        CacheParameterGroupName=default_name,
    )["CacheParameterGroups"]
    assert len(still_listed) == 1, still_listed
    assert still_listed[0]["CacheParameterGroupFamily"] == "redis7", still_listed[0]

    default_before = ec.describe_cache_parameters(CacheParameterGroupName=default_name)["Parameters"]
    default_baseline = next(p for p in default_before if p["ParameterName"] == "maxmemory-policy")["ParameterValue"]
    default_target = "noeviction" if default_baseline != "noeviction" else "allkeys-lru"

    _assert_error(lambda: ec.modify_cache_parameter_group(
        CacheParameterGroupName=default_name,
        ParameterNameValues=[
            {"ParameterName": "maxmemory-policy", "ParameterValue": default_target},
        ],
    ), ("InvalidParameterValueException", "Cannot modify a default parameter group."))

    # Independent read: the failed modify left the default group's parameter value unchanged.
    default_after = ec.describe_cache_parameters(CacheParameterGroupName=default_name)["Parameters"]
    default_unchanged = next(p for p in default_after if p["ParameterName"] == "maxmemory-policy")
    assert default_unchanged["ParameterValue"] == default_baseline, default_unchanged


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
