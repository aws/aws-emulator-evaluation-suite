"""modify-parameter-group-batch-atomicity-on-unknown-parameter."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-parameter-group-batch-atomicity-on-unknown-parameter"
GROUP = 'parameter-group'
SERVICES = ['elasticache']

_FAMILY = "redis7"
_UNKNOWN = "sim2real-not-a-real-parameter"
_ILLEGAL_VALUE = "sim2real-not-a-legal-value"


def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _error_code(fn):
    """Call fn(); return (code, message) from the ClientError it must raise.

    An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


# ElastiCache briefly locks a parameter after a Modify/Reset touches it ("The parameter <name>
# is being modified."); only this one code is retried, so a real refusal is never swallowed.
_APPLYING = "InvalidCacheParameterGroupState"


def _when_settled(fn, attempts=12, delay_s=10.0):
    """Call fn(), retrying only while the group reports InvalidCacheParameterGroupState."""
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if _fault_base(code or "") != _APPLYING:
                raise
            last = exc
            time.sleep(delay_s)
    raise last


def _error_code_when_settled(fn, attempts=12, delay_s=10.0):
    """(code, message) for fn(), skipping past the transient applying-state refusal."""
    last = (None, None)
    for _ in range(attempts):
        code, message = _error_code(fn)
        if _fault_base(code or "") != _APPLYING:
            return code, message
        last = (code, message)
        time.sleep(delay_s)
    raise AssertionError(
        f"the parameter group never left the applying state: last refusal was {last!r}"
    )


def _assert_error(fn, expected, what):
    """Assert fn() fails with the (code, message) pair `expected`; return the code.

    An unknown name and an illegal value share InvalidParameterValue; only the message differs.
    """
    code, message = _error_code_when_settled(fn)
    assert _fault_base(code) == _fault_base(expected[0]), (
        f"{what}: expected {expected[0]}, got {code} ({message!r})"
    )
    assert message == expected[1], (
        f"{what}: the refusal must name its own reason; expected {expected[1]!r}, got "
        f"{message!r}"
    )
    return code


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


def _all_params(ec, group_name):
    """Every Parameter in `group_name`, keyed by name, following the Marker pagination."""
    out = {}
    marker = None
    while True:
        kwargs = {"CacheParameterGroupName": group_name}
        if marker:
            kwargs["Marker"] = marker
        resp = ec.describe_cache_parameters(**kwargs)
        for p in resp.get("Parameters", []):
            out[p["ParameterName"]] = p
        marker = resp.get("Marker")
        if not marker:
            return out


def _user_sourced(ec, group_name):
    """The set of parameter names in `group_name` that report Source='user'."""
    return {n for n, p in _all_params(ec, group_name).items() if p.get("Source") == "user"}


def _pick_two_modifiable(defaults):
    """Two distinct modifiable parameters with an enumerated AllowedValues and a value we
    can flip to something legal-but-different. Returns [(name, new_value), ...]."""
    picked = []
    for p in defaults:
        if not p.get("IsModifiable"):
            continue
        allowed = p.get("AllowedValues") or ""
        if "," not in allowed:
            continue
        members = [v.strip() for v in allowed.split(",") if v.strip()]
        alt = next((v for v in members if v != (p.get("ParameterValue") or "")), None)
        if alt is None:
            continue
        picked.append((p["ParameterName"], alt))
        if len(picked) == 2:
            break
    return picked


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ModifyCacheParameterGroup batch with one unknown name or one illegal value is refused
    whole: no member is applied, each defect has its own message, and a valid batch still applies.

    Reference: https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_ModifyCacheParameterGroup.html
    """
    ec = ctx.client("elasticache")

    defaults = ec.describe_engine_default_parameters(
        CacheParameterGroupFamily=_FAMILY,
    )["EngineDefaults"]["Parameters"]
    pair = _pick_two_modifiable(defaults)
    assert len(pair) == 2, (
        f"{_FAMILY} engine defaults do not publish two modifiable enumerated parameters; "
        f"found {pair}"
    )
    (name_a, value_a), (name_b, value_b) = pair
    allowed_a = next(
        p.get("AllowedValues") for p in defaults if p["ParameterName"] == name_a
    )

    group = ctx.unique_name("sim2real-behav-ecpg-atomic-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=group,
        CacheParameterGroupFamily=_FAMILY,
        Description="sim2real batch atomicity check",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_parameter_group_when_ready(ec, group))

    # ---- valid setup: a two-member batch DOES work --------------------------------
    assert _user_sourced(ec, group) == set(), (
        f"a brand-new parameter group must have no user-sourced parameters, got "
        f"{_user_sourced(ec, group)}"
    )
    _when_settled(lambda: ec.modify_cache_parameter_group(
        CacheParameterGroupName=group,
        ParameterNameValues=[
            {"ParameterName": name_a, "ParameterValue": value_a},
            {"ParameterName": name_b, "ParameterValue": value_b},
        ],
    ))
    both = _user_sourced(ec, group)
    assert both == {name_a, name_b}, (
        f"a valid two-member batch must apply both members; user-sourced set is {both}, "
        f"expected {{{name_a!r}, {name_b!r}}}"
    )

    # ---- clean slate: reset both back to the engine default -----------------------
    _when_settled(lambda: ec.reset_cache_parameter_group(
        CacheParameterGroupName=group,
        ParameterNameValues=[
            {"ParameterName": name_a},
            {"ParameterName": name_b},
        ],
    ))
    cleared = _user_sourced(ec, group)
    assert cleared == set(), (
        f"ResetCacheParameterGroup must return both parameters to the engine default; "
        f"still user-sourced: {cleared}"
    )

    # ---- break exactly one thing: one batch member names a parameter that does not exist
    all_names = set(_all_params(ec, group))
    assert _UNKNOWN not in all_names, f"{_UNKNOWN!r} unexpectedly exists in {group}"
    _assert_error(
        lambda: ec.modify_cache_parameter_group(
            CacheParameterGroupName=group,
            ParameterNameValues=[
                {"ParameterName": name_a, "ParameterValue": value_a},
                {"ParameterName": _UNKNOWN, "ParameterValue": "1"},
            ],
        ),
        ("InvalidParameterValueException", f"Could not find parameter with name: {_UNKNOWN}"),
        f"mixed batch [{name_a} (valid), {_UNKNOWN} (unknown)]",
    )

    # ---- effect absent: the WHOLE batch was discarded, valid member included -------
    after = _user_sourced(ec, group)
    assert after == set(), (
        f"PARTIAL WRITE: the rejected mixed batch still applied {after}. "
        f"ModifyCacheParameterGroup must be all-or-nothing, so {name_a!r} must remain at "
        f"its engine default after the batch was refused"
    )
    assert _UNKNOWN not in set(_all_params(ec, group)), (
        f"the rejected batch created the unknown parameter {_UNKNOWN!r} in the group"
    )

    # ---- control case still works: the valid member alone applies ------------------
    _when_settled(lambda: ec.modify_cache_parameter_group(
        CacheParameterGroupName=group,
        ParameterNameValues=[{"ParameterName": name_a, "ParameterValue": value_a}],
    ))
    control = _user_sourced(ec, group)
    assert control == {name_a}, (
        f"control case failed: after the rejected batch, the valid member alone no longer "
        f"applies; user-sourced set is {control}, expected {{{name_a!r}}}"
    )

    # ---- a SECOND, independent defect: a real name carrying an ILLEGAL VALUE ---------
    # `name_b` is still at its engine default, so its absence afterwards proves the batch
    # was discarded whole.
    assert name_b not in _user_sourced(ec, group), (
        f"test setup error: {name_b!r} must be at its engine default before the second "
        f"negative, so its absence afterwards means something; user-sourced is "
        f"{_user_sourced(ec, group)}"
    )
    _assert_error(
        lambda: ec.modify_cache_parameter_group(
            CacheParameterGroupName=group,
            ParameterNameValues=[
                {"ParameterName": name_b, "ParameterValue": value_b},
                {"ParameterName": name_a, "ParameterValue": _ILLEGAL_VALUE},
            ],
        ),
        ("InvalidParameterValueException", f"invalid parameter value, allowed values are:{allowed_a}"),
        f"mixed batch [{name_b} (valid), {name_a}={_ILLEGAL_VALUE!r} (illegal value)]",
    )
    after_value = _user_sourced(ec, group)
    assert after_value == {name_a}, (
        f"PARTIAL WRITE: the batch refused for an illegal VALUE still applied {name_b!r}; "
        f"user-sourced set is {after_value}, expected exactly {{{name_a!r}}} (unchanged from "
        f"before the refused batch)"
    )
    assert _all_params(ec, group)[name_a]["ParameterValue"] == value_a, (
        f"the refused batch overwrote {name_a!r} with the illegal value; it is now "
        f"{_all_params(ec, group)[name_a].get('ParameterValue')!r}, expected {value_a!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
