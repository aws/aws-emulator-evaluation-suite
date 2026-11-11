"""cluster-parameter-numeric-precision-round-trip."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "cluster-parameter-numeric-precision-round-trip"
GROUP = "representation"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A large integer parameter value set via ModifyDBClusterParameterGroup on a real Aurora
    cluster parameter group family is returned byte-identical (same decimal string, no
    truncation/rounding to a smaller integer width or float) by DescribeDBClusterParameters."""
    rds = ctx.client("rds")

    family = _pick_cluster_parameter_group_family(ctx, rds)
    group_name = ctx.unique_name("sim2real-clusterpg-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=group_name,
        DBParameterGroupFamily=family,
        Description="sim2real numeric precision round-trip test",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=group_name)
    )

    param_name, target_value = _find_large_integer_parameter(rds, family)

    rds.modify_db_cluster_parameter_group(
        DBClusterParameterGroupName=group_name,
        Parameters=[
            {
                "ParameterName": param_name,
                "ParameterValue": target_value,
                "ApplyMethod": "pending-reboot",
            }
        ],
    )

    stored = _find_current_parameter_value(rds, group_name, param_name)
    assert stored == target_value, (
        f"parameter {param_name!r} set to {target_value!r} round-tripped as {stored!r} -- "
        f"a byte-for-byte mismatch means the value was truncated/rounded/reformatted"
    )

    # A second, independent read must show the exact same string -- no drift between reads.
    stored_again = _find_current_parameter_value(rds, group_name, param_name)
    assert stored_again == target_value, (
        f"second DescribeDBClusterParameters read returned {stored_again!r}, expected "
        f"{target_value!r} unchanged"
    )


_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")


def _pick_cluster_parameter_group_family(ctx, rds) -> str:
    for engine in ("aurora-mysql", "aurora-postgresql"):
        versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)[
            "DBEngineVersions"
        ]
        if versions:
            return versions[0]["DBParameterGroupFamily"]

    raise AssertionError(
        "neither aurora-mysql nor aurora-postgresql has a default engine version available "
        "in this account/region, so no DBClusterParameterGroup family could be determined"
    )


def _find_large_integer_parameter(rds, family: str) -> tuple[str, str]:
    """Return (ParameterName, str(upper_bound)) for the modifiable integer parameter in
    `family`'s engine defaults with the single largest numeric AllowedValues upper bound."""
    best_name = None
    best_upper = -1
    paginator = rds.get_paginator("describe_engine_default_cluster_parameters")
    for page in paginator.paginate(DBParameterGroupFamily=family):
        for p in page["EngineDefaults"]["Parameters"]:
            if not p.get("IsModifiable") or p.get("DataType") != "integer":
                continue
            m = _RANGE_RE.match(p.get("AllowedValues") or "")
            if not m:
                continue
            upper = int(m.group(2))
            if upper > best_upper:
                best_upper = upper
                best_name = p["ParameterName"]
    if best_name is None:

        raise AssertionError(
            f"no modifiable integer parameter with a plain numeric range was found in "
            f"engine-default parameters for family {family!r}"
        )
    return best_name, str(best_upper)


def _find_current_parameter_value(rds, group_name: str, param_name: str) -> str | None:
    paginator = rds.get_paginator("describe_db_cluster_parameters")
    for page in paginator.paginate(DBClusterParameterGroupName=group_name):
        for p in page["Parameters"]:
            if p["ParameterName"] == param_name:
                return p.get("ParameterValue")
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
