"""parameter-value-rejections-leave-group-unchanged."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-value-rejections-leave-group-unchanged"
GROUP = 'parameter-groups'
SERVICES = ['memorydb']

def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _params(m, group: str) -> dict:
    """Every parameter of ``group`` by name, across all pages."""
    out = {}
    for page in m.get_paginator("describe_parameters").paginate(ParameterGroupName=group):
        for p in page["Parameters"]:
            out[p["Name"]] = p
    return out


def _values(m, group: str) -> dict:
    return {n: p.get("Value") for n, p in _params(m, group).items()}


def _drop_pg(m, name: str) -> None:
    try:
        m.delete_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterGroupNotFoundFault":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateParameterGroup refuses an out-of-enum, out-of-range or non-integer value, an unknown or duplicate
    name, more than 20 names and a batch with one bad member, each atomically; the default group
    refuses any change, and a valid update still lands.
    """
    m = ctx.client("memorydb")
    name = ctx.unique_name("sim2real-mdb-")
    missing = name + "-none"
    m.create_parameter_group(ParameterGroupName=name, Family="memorydb_valkey7")
    ctx.on_cleanup(lambda: _drop_pg(m, name))
    params = _params(m, name)
    before = {n: p.get("Value") for n, p in params.items()}
    policy_allowed = params["maxmemory-policy"]["AllowedValues"]
    timeout_allowed = params["timeout"]["AllowedValues"]
    defrag_allowed = params["activedefrag"]["AllowedValues"]
    # 21 distinct parameters, each set to its current value, so the batch's only fault is its size.
    batch = sorted((n, p["Value"]) for n, p in params.items() if p.get("Value"))[:21]
    assert len(batch) == 21, f"the group has only {len(batch)} parameters with a value"

    def upd(*pairs):
        return lambda: m.update_parameter_group(ParameterGroupName=name, ParameterNameValues=[
            {"ParameterName": k, "ParameterValue": v} for k, v in pairs])

    refusals = [
        ("enum", upd(("maxmemory-policy", "bogus")), "InvalidParameterValueException",
         f"invalid parameter value, allowed values are:{policy_allowed}"),
        ("bool", upd(("activedefrag", "maybe")), "InvalidParameterValueException",
         f"invalid parameter value, allowed values are:{defrag_allowed}"),
        ("range", upd(("timeout", "19")), "InvalidParameterValueException",
         f"value:19 is outside of range:{timeout_allowed}"),
        ("negative", upd(("timeout", "-5")), "InvalidParameterValueException",
         f"value:-5 is outside of range:{timeout_allowed}"),
        ("non-integer", upd(("timeout", "abc")), "InvalidParameterValueException", "invalid integer value: abc"),
        ("unknown", upd(("no-such-param", "1")), "InvalidParameterValueException",
         "Could not find parameter with name: no-such-param"),
        ("duplicate", upd(("timeout", "100"), ("timeout", "200")), "InvalidParameterValueException",
         "Duplicate parameters specified in the same call"),
        ("too-many", upd(*batch), "InvalidParameterCombinationException",
         "Cannot modify more than 20 parameters in a single request"),
        ("partial", upd(("timeout", "500"), ("maxmemory-policy", "bogus")), "InvalidParameterValueException",
         f"invalid parameter value, allowed values are:{policy_allowed}"),
    ]
    for label, fn, want_code, want_msg in refusals:
        code, msg = _error(fn)
        assert code == want_code, f"{label}: expected {want_code}, got {code}: {msg!r}"
        assert msg == want_msg, f"{label}: message was {msg!r}"
        assert _values(m, name) == before, f"refused {label} update changed the group"

    code, msg = _error(lambda: m.update_parameter_group(
        ParameterGroupName="default.memorydb-valkey7",
        ParameterNameValues=[{"ParameterName": "timeout", "ParameterValue": "300"}]))
    assert (code, msg) == ("InvalidParameterValueException", "Cannot modify a default parameter group."), (
        f"updating the default group gave {code}: {msg!r}"
    )
    code, msg = _error(lambda: m.update_parameter_group(
        ParameterGroupName=missing, ParameterNameValues=[{"ParameterName": "timeout", "ParameterValue": "300"}]))
    assert code == "ParameterGroupNotFoundFault", f"updating a missing group gave {code}: {msg!r}"
    assert msg == f"ParameterGroup not found: {missing}", f"message was {msg!r}"

    m.update_parameter_group(ParameterGroupName=name, ParameterNameValues=[
        {"ParameterName": "timeout", "ParameterValue": "20"}])
    after = _values(m, name)
    assert after["timeout"] == "20", f"the boundary value 20 did not apply: {after['timeout']!r}"
    assert {k: v for k, v in after.items() if k != "timeout"} == {k: v for k, v in before.items() if k != "timeout"}, (
        "a single-parameter update changed another parameter"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
