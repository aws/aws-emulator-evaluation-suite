"""reset-parameter-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "reset-parameter-group"
GROUP = 'parameter_groups'
SERVICES = ['rds']

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _params(rds, name):
    """All pages of DescribeDBParameters for name, keyed by ParameterName."""
    return {
        p["ParameterName"]: p
        for page in rds.get_paginator("describe_db_parameters").paginate(
            DBParameterGroupName=name
        )
        for p in page["Parameters"]
    }


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResetDBParameterGroup with ResetAllParameters clears a customized value back to the
    engine default, proven by an independent DescribeDBParameters read taken after the reset —
    not merely "not 200"."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral test parameter group",
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=name))
    rds.modify_db_parameter_group(
        DBParameterGroupName=name,
        Parameters=[
            {
                "ParameterName": "max_connections",
                "ParameterValue": "200",
                "ApplyMethod": "pending-reboot",
            }
        ],
    )

    # Positive control: prove the modify actually took hold before reset is exercised, so a
    # no-op modify combined with a no-op reset cannot pass by both doing nothing.
    modified = _params(rds, name)
    assert "max_connections" in modified, (
        "max_connections must be present in DescribeDBParameters after ModifyDBParameterGroup; "
        f"got parameters {sorted(modified)!r}"
    )
    assert modified["max_connections"].get("ParameterValue") == "200", (
        "test precondition: ModifyDBParameterGroup must have actually set max_connections=200 "
        f"before reset is exercised; got {modified['max_connections'].get('ParameterValue')!r}"
    )
    assert modified["max_connections"].get("Source") == "user", (
        "test precondition: a customized parameter must report Source='user'; got "
        f"{modified['max_connections'].get('Source')!r}"
    )

    rds.reset_db_parameter_group(DBParameterGroupName=name, ResetAllParameters=True)

    reset = _params(rds, name)
    assert "max_connections" in reset, (
        "max_connections must still be present (as its engine default) in DescribeDBParameters "
        f"after ResetDBParameterGroup; got parameters {sorted(reset)!r}"
    )
    val = reset["max_connections"].get("ParameterValue")
    assert val != "200", (
        "ResetDBParameterGroup(ResetAllParameters=True) must clear max_connections back to the "
        f"engine default, not leave the customized value; still {val!r}"
    )
    assert reset["max_connections"].get("Source") != "user", (
        "after a full reset max_connections must no longer report Source='user' (the mark of a "
        f"customized value); got {reset['max_connections'].get('Source')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
