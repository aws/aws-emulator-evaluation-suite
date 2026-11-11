"""parameter-value-outside-allowed-values-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-value-outside-allowed-values-rejected"
GROUP = 'parameter-group'
SERVICES = ['elasticache']

_FAMILY = "redis7"


def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _error(fn, what):
    """Call fn(); return (code, message) from the ClientError it must raise.

    An unexpected SUCCESS raises rather than reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what}: real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _assert_error(fn, expected, what):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, message = _error(fn, what)
    assert _fault_base(code) == _fault_base(expected[0]), (
        f"{what}: expected {expected[0]}, got {code}"
    )
    assert message == expected[1], (
        f"{what}: expected message {expected[1]!r}, got {message!r}"
    )
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


def _param(ec, group_name, parameter_name):
    """The single Parameter entry `parameter_name` inside `group_name`, or None."""
    marker = None
    while True:
        kwargs = {"CacheParameterGroupName": group_name}
        if marker:
            kwargs["Marker"] = marker
        resp = ec.describe_cache_parameters(**kwargs)
        for p in resp.get("Parameters", []):
            if p.get("ParameterName") == parameter_name:
                return p
        marker = resp.get("Marker")
        if not marker:
            return None


def _enumerated_values(allowed):
    """Split an AllowedValues enumeration ('a,b,c') into its members; [] if it is a range."""
    if not allowed or "," not in allowed:
        return []
    return [v.strip() for v in allowed.split(",") if v.strip()]


_RANGE_RE = re.compile(r"^\d+-\d*$")


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCacheParameterGroup rejects a value outside the parameter's AllowedValues and a
    non-numeric value for an integer parameter with InvalidParameterValueException and the exact
    message; the prior legal value survives each rejection and a later legal value still applies.
    """
    ec = ctx.client("elasticache")

    defaults = ec.describe_engine_default_parameters(
        CacheParameterGroupFamily=_FAMILY,
    )["EngineDefaults"]["Parameters"]
    by_name = {p["ParameterName"]: p for p in defaults}

    policy = by_name.get("maxmemory-policy")
    assert policy is not None, (
        f"{_FAMILY} engine defaults do not publish 'maxmemory-policy'; "
        f"published names: {sorted(by_name)[:20]}"
    )
    legal_policies = _enumerated_values(policy.get("AllowedValues"))
    assert len(legal_policies) >= 2, (
        f"maxmemory-policy AllowedValues must be an enumeration with >=2 members, "
        f"got {policy.get('AllowedValues')!r}"
    )
    assert "allkeys-lru" in legal_policies, (
        f"maxmemory-policy AllowedValues is missing the documented 'allkeys-lru': "
        f"{legal_policies}"
    )

    integer_param = next(
        (
            p for p in defaults
            if p.get("IsModifiable")
            and p.get("DataType") == "integer"
            and _RANGE_RE.match(p.get("AllowedValues") or "")
        ),
        None,
    )
    assert integer_param is not None, (
        f"{_FAMILY} engine defaults publish no modifiable integer parameter with a "
        f"range-shaped AllowedValues; cannot test DataType enforcement"
    )
    int_name = integer_param["ParameterName"]
    int_allowed = integer_param["AllowedValues"]

    group = ctx.unique_name("sim2real-behav-ecpg-legality-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=group,
        CacheParameterGroupFamily=_FAMILY,
        Description="sim2real parameter-value legality check",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_parameter_group_when_ready(ec, group))

    first_legal = next(v for v in legal_policies if v != "allkeys-lru")
    ec.modify_cache_parameter_group(
        CacheParameterGroupName=group,
        ParameterNameValues=[
            {"ParameterName": "maxmemory-policy", "ParameterValue": first_legal},
        ],
    )
    applied = _param(ec, group, "maxmemory-policy")
    assert applied is not None, f"maxmemory-policy vanished from {group} after a legal modify"
    assert applied["ParameterValue"] == first_legal, (
        f"legal value {first_legal!r} did not apply; DescribeCacheParameters reports "
        f"{applied.get('ParameterValue')!r}"
    )
    assert applied.get("Source") == "user", (
        f"a user-modified parameter must report Source='user', got "
        f"{applied.get('Source')!r} (an emulator that never re-sources a modified "
        f"parameter cannot distinguish user values from engine defaults)"
    )

    bogus_policy = "sim2real-not-a-maxmemory-policy"
    assert bogus_policy not in legal_policies, bogus_policy
    _assert_error(
        lambda: ec.modify_cache_parameter_group(
            CacheParameterGroupName=group,
            ParameterNameValues=[
                {"ParameterName": "maxmemory-policy", "ParameterValue": bogus_policy},
            ],
        ),
        (
            "InvalidParameterValueException",
            f"invalid parameter value, allowed values are:{policy['AllowedValues']}",
        ),
        f"maxmemory-policy={bogus_policy!r} (AllowedValues={legal_policies})",
    )

    after_reject = _param(ec, group, "maxmemory-policy")
    assert after_reject is not None, "maxmemory-policy vanished after a rejected modify"
    assert after_reject["ParameterValue"] == first_legal, (
        f"REJECTED modify still mutated state: maxmemory-policy is now "
        f"{after_reject.get('ParameterValue')!r}, expected the pre-reject value "
        f"{first_legal!r}"
    )

    int_min = int(int_allowed.split("-", 1)[0])
    ec.modify_cache_parameter_group(
        CacheParameterGroupName=group,
        ParameterNameValues=[
            {"ParameterName": int_name, "ParameterValue": str(int_min)},
        ],
    )
    int_legal = _param(ec, group, int_name)
    assert int_legal is not None, f"{int_name} vanished after a legal modify"
    assert int_legal.get("ParameterValue") == str(int_min), (
        f"legal value {int_min} did not apply to {int_name}; DescribeCacheParameters "
        f"reports {int_legal.get('ParameterValue')!r}"
    )
    assert int_legal.get("Source") == "user", (
        f"a user-modified parameter must report Source='user', got "
        f"{int_legal.get('Source')!r} — without this, the later rejection of a "
        f"non-numeric value is indistinguishable from a target that refuses every "
        f"modification of {int_name}"
    )

    _assert_error(
        lambda: ec.modify_cache_parameter_group(
            CacheParameterGroupName=group,
            ParameterNameValues=[
                {"ParameterName": int_name, "ParameterValue": "sim2real-not-a-number"},
            ],
        ),
        ("InvalidParameterValueException", "invalid integer value: sim2real-not-a-number"),
        f"{int_name}='sim2real-not-a-number' (DataType=integer, AllowedValues={int_allowed!r})",
    )

    int_after = _param(ec, group, int_name)
    assert int_after is not None, f"{int_name} vanished after a rejected modify"
    assert int_after.get("Source") == "user", (
        f"REJECTED modify cleared the prior legal value's Source on {int_name} "
        f"(Source={int_after.get('Source')!r}); expected the pre-reject 'user' source "
        f"to survive"
    )
    assert int_after.get("ParameterValue") == str(int_min), (
        f"REJECTED modify still mutated {int_name}: now "
        f"{int_after.get('ParameterValue')!r}, expected the pre-reject value "
        f"{int_min!r} to survive"
    )

    ec.modify_cache_parameter_group(
        CacheParameterGroupName=group,
        ParameterNameValues=[
            {"ParameterName": "maxmemory-policy", "ParameterValue": "allkeys-lru"},
        ],
    )
    final = _param(ec, group, "maxmemory-policy")
    assert final is not None and final["ParameterValue"] == "allkeys-lru", (
        f"control case failed: after two rejections a legal value no longer applies; "
        f"maxmemory-policy is {final and final.get('ParameterValue')!r}"
    )

    _delete_parameter_group_when_ready(ec, group)
    assert _describe_one(
        ec.describe_cache_parameter_groups,
        "CacheParameterGroups",
        "CacheParameterGroupName",
        group,
    ) is None, f"{group} still resolves after delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
