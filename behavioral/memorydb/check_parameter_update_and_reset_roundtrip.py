"""parameter-update-and-reset-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-update-and-reset-roundtrip"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom valkey group starts equal to the family default, takes three updates, a targeted
    reset restores only the named parameter, and a full reset restores every value.
    """
    m = ctx.client("memorydb")
    name = ctx.unique_name("sim2real-mdb-")
    created = m.create_parameter_group(ParameterGroupName=name, Family="memorydb_valkey7",
                                       Tags=[{"Key": "sim2real", "Value": CHECK}])["ParameterGroup"]
    ctx.on_cleanup(lambda: _drop_pg(m, name))
    assert created["Family"] == "memorydb_valkey7", f"group created in family {created['Family']!r}"
    assert created["Description"] == " ", f"an omitted description reads back as {created['Description']!r}"

    baseline = _values(m, "default.memorydb-valkey7")
    start = _values(m, name)
    assert start == baseline, f"a new group differs from its family default in {sorted(k for k in start if start.get(k) != baseline.get(k))!r}"
    for key in ("maxmemory-policy", "timeout", "activedefrag"):
        assert key in baseline, f"family default lacks {key!r}"
    changes = {"maxmemory-policy": "allkeys-lru", "timeout": "300", "activedefrag": "yes"}
    assert all(baseline[k] != v for k, v in changes.items()), f"defaults already equal the updates: {baseline!r}"

    m.update_parameter_group(ParameterGroupName=name, ParameterNameValues=[
        {"ParameterName": k, "ParameterValue": v} for k, v in changes.items()])
    updated = _values(m, name)
    for k, v in changes.items():
        assert updated[k] == v, f"{k} reads {updated[k]!r} after update to {v!r}"
    untouched = {k: v for k, v in updated.items() if k not in changes}
    assert untouched == {k: v for k, v in baseline.items() if k not in changes}, "an update changed another parameter"

    m.reset_parameter_group(ParameterGroupName=name, ParameterNames=["timeout"])
    after_one = _values(m, name)
    assert after_one["timeout"] == baseline["timeout"], f"timeout after targeted reset {after_one['timeout']!r}"
    assert after_one["maxmemory-policy"] == "allkeys-lru", f"targeted reset touched maxmemory-policy: {after_one['maxmemory-policy']!r}"
    assert after_one["activedefrag"] == "yes", f"targeted reset touched activedefrag: {after_one['activedefrag']!r}"

    m.reset_parameter_group(ParameterGroupName=name, AllParameters=True)
    assert _values(m, name) == baseline, "a full reset did not restore every family default"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
