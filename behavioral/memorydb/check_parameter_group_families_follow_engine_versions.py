"""parameter-group-families-follow-engine-versions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-group-families-follow-engine-versions"
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


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every parameter group family DescribeEngineVersions names for valkey and for redis accepts
    a custom group whose parameter names equal that family's default group; the two engines name
    disjoint families, and a family the catalogue does not name is refused.
    """
    m = ctx.client("memorydb")
    base = ctx.unique_name("sim2real-mdb-")
    families = {}
    for engine in ("valkey", "redis"):
        rows = [v for page in m.get_paginator("describe_engine_versions").paginate(Engine=engine)
                for v in page["EngineVersions"]]
        assert rows, f"no {engine} engine versions listed"
        assert all(v["Engine"] == engine for v in rows), f"Engine={engine} filter returned {rows!r}"
        families[engine] = {v["ParameterGroupFamily"] for v in rows}
    assert not families["valkey"] & families["redis"], f"engines share families {families!r}"

    for i, family in enumerate(sorted(families["valkey"] | families["redis"])):
        name = f"{base}-f{i}"
        pg = m.create_parameter_group(ParameterGroupName=name, Family=family)["ParameterGroup"]
        ctx.on_cleanup(lambda n=name: _drop_pg(m, n))
        assert pg["Family"] == family, f"group for {family!r} reports family {pg['Family']!r}"
        default = "default." + family.replace("_", "-")
        assert set(_params(m, name)) == set(_params(m, default)), (
            f"a {family} group's parameter names differ from {default}"
        )

    bogus = sorted(families["valkey"])[0] + "x"
    code, msg = _error(lambda: m.create_parameter_group(ParameterGroupName=base + "-bad", Family=bogus))
    ctx.on_cleanup(lambda: _drop_pg(m, base + "-bad"))
    assert code == "InvalidParameterValueException", f"unknown family {bogus!r} gave {code}: {msg!r}"
    assert msg == f"ParameterGroupFamily {bogus} is not a valid parameter group family.", f"message was {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
