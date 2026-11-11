"""describe-parameters-default-group-matches-source."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-parameters-default-group-matches-source"
GROUP = "control-plane"
SERVICES = ["dax"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeParameters on a new parameter group returns exactly DescribeDefaultParameters' names, each with
    the default's ParameterValue, IsModifiable and ChangeType; values are compared because DAX reports
    Source "user" for every parameter."""
    dax = ctx.client("dax")
    default_params = _list_all(ctx, lambda **kw: dax.describe_default_parameters(**kw), "Parameters")
    assert default_params, "expected DAX to expose a non-empty default parameter catalog"
    default_names = {p["ParameterName"] for p in default_params}

    name = ctx.unique_name("sim2real-dax-pg-")
    dax.create_parameter_group(ParameterGroupName=name)
    ctx.on_cleanup(lambda: dax.delete_parameter_group(ParameterGroupName=name))

    group_params = _list_all(
        ctx, lambda **kw: dax.describe_parameters(ParameterGroupName=name, **kw), "Parameters"
    )
    group_names = {p["ParameterName"] for p in group_params}
    assert group_names == default_names, (
        f"fresh parameter group's parameter names diverged from the default catalog: "
        f"missing={default_names - group_names} extra={group_names - default_names}"
    )

    # A brand-new, never-modified group's parameters must trace back to the engine
    # defaults not just by value (DAX attributes Source as "user" even for an
    # unmodified group, so value equality is the correct drift check) but also by the
    # per-parameter metadata the engine's default catalog is the sole source of truth
    # for: IsModifiable and ChangeType are properties of the parameter itself, not of
    # the group, so they must match the default catalog's own entry exactly rather
    # than merely lie within the modelled enum.
    default_by_name = {p["ParameterName"]: p for p in default_params}
    for p in group_params:
        default = default_by_name[p["ParameterName"]]
        assert p.get("ParameterValue") == default.get("ParameterValue"), (
            f"{p['ParameterName']} value diverged from engine default on a fresh group: "
            f"{p.get('ParameterValue')!r} != {default.get('ParameterValue')!r}"
        )
        assert p.get("IsModifiable") == default.get("IsModifiable"), (
            f"{p['ParameterName']} IsModifiable diverged from the default catalog: "
            f"{p.get('IsModifiable')!r} != {default.get('IsModifiable')!r}"
        )
        assert p.get("ChangeType") == default.get("ChangeType"), (
            f"{p['ParameterName']} ChangeType diverged from the default catalog: "
            f"{p.get('ChangeType')!r} != {default.get('ChangeType')!r}"
        )


def _list_all(ctx, call, field):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = call(**kwargs)
        out.extend(resp[field])
        token = resp.get("NextToken")
        if not token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
