"""parameter-numeric-precision-round-trip."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "parameter-numeric-precision-round-trip"
GROUP = "representation"
SERVICES = ["rds"]

_PARAM_NAME = "random_page_cost"
_PARAM_VALUE = "1.123456"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A decimal-precision numeric DB parameter value set via ModifyDBParameterGroup is
    returned with the exact same string precision on DescribeDBParameters -- not rounded,
    truncated, or reformatted to a different number of decimal digits."""
    rds = ctx.client("rds")

    versions = rds.describe_db_engine_versions(Engine="postgres", DefaultOnly=True)["DBEngineVersions"]
    if not versions:
        raise AssertionError("no default postgres engine version available to source a parameter group family")
    family = versions[0]["DBParameterGroupFamily"]

    pg_name = ctx.unique_name("sim2real-pg-precision-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily=family,
        Description="sim2real behavioral check",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))

    rds.modify_db_parameter_group(
        DBParameterGroupName=pg_name,
        Parameters=[{"ParameterName": _PARAM_NAME, "ParameterValue": _PARAM_VALUE, "ApplyMethod": "immediate"}],
    )

    param = _describe_parameter(rds, pg_name, _PARAM_NAME)
    assert param is not None, f"{_PARAM_NAME} not present in parameter group after modification"
    assert param["ParameterValue"] == _PARAM_VALUE, (
        f"expected exact precision {_PARAM_VALUE!r}, got {param['ParameterValue']!r}"
    )

    # A second, independent read must show the exact same string -- no drift between reads.
    param_again = _describe_parameter(rds, pg_name, _PARAM_NAME)
    assert param_again is not None, f"{_PARAM_NAME} disappeared from parameter group on second read"
    assert param_again["ParameterValue"] == _PARAM_VALUE, (
        f"second DescribeDBParameters read returned {param_again['ParameterValue']!r}, expected "
        f"{_PARAM_VALUE!r} unchanged"
    )


def _describe_parameter(rds: Any, pg_name: str, param_name: str) -> dict[str, Any] | None:
    paginator = rds.get_paginator("describe_db_parameters")
    for page in paginator.paginate(DBParameterGroupName=pg_name):
        for p in page["Parameters"]:
            if p["ParameterName"] == param_name:
                return p
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
