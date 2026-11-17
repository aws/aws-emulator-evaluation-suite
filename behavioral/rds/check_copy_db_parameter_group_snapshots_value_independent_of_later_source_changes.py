"""copy-db-parameter-group-snapshots-value-independent-of-later-source-changes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "copy-db-parameter-group-snapshots-value-independent-of-later-source-changes"
GROUP = "parameter_groups"
SERVICES = ["rds"]

_PARAM = "auto_explain.log_min_duration"


def _default_param_family(rds, engine: str) -> str:
    """The DBParameterGroupFamily of the current default version for *engine*."""
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
        "DBEngineVersions", []
    )
    return versions[0]["DBParameterGroupFamily"]


def _param_value(rds, group_name: str, name: str) -> str:
    """*name*'s current ParameterValue in *group_name*, across every page."""
    for page in rds.get_paginator("describe_db_parameters").paginate(DBParameterGroupName=group_name):
        for p in page["Parameters"]:
            if p["ParameterName"] == name:
                return p["ParameterValue"]
    raise AssertionError(f"{name!r} is not a parameter of {group_name!r}")


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyDBParameterGroup carries a changed parameter's value at the moment of the copy, and a
    later change to the source does not reach the already-made copy.
    """
    rds = ctx.client("rds")
    family = _default_param_family(rds, "postgres")

    src = ctx.unique_name("sim2real-behav-pg-src-")
    rds.create_db_parameter_group(
        DBParameterGroupName=src,
        DBParameterGroupFamily=family,
        Description="sim2real behavioral copy-isolation source",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=src))

    rds.modify_db_parameter_group(
        DBParameterGroupName=src,
        Parameters=[{"ParameterName": _PARAM, "ParameterValue": "500", "ApplyMethod": "immediate"}],
    )
    assert _param_value(rds, src, _PARAM) == "500", (
        f"expected {_PARAM} on the source group to read back as '500' right after modifying it"
    )

    tgt = ctx.unique_name("sim2real-behav-pg-tgt-")
    rds.copy_db_parameter_group(
        SourceDBParameterGroupIdentifier=src,
        TargetDBParameterGroupIdentifier=tgt,
        TargetDBParameterGroupDescription="sim2real behavioral copy-isolation target",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=tgt))
    assert _param_value(rds, tgt, _PARAM) == "500", (
        f"expected the copy to carry the source's value '500' for {_PARAM} at the moment of copy"
    )

    rds.modify_db_parameter_group(
        DBParameterGroupName=src,
        Parameters=[{"ParameterName": _PARAM, "ParameterValue": "900", "ApplyMethod": "immediate"}],
    )
    assert _param_value(rds, src, _PARAM) == "900", (
        f"expected {_PARAM} on the source group to read back as '900' after the second modify"
    )

    assert _param_value(rds, tgt, _PARAM) == "500", (
        "the copy must stay at the value it held when it was made ('500'); a later change to "
        "the source must not reach it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
