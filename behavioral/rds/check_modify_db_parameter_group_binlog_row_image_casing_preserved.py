"""modify-db-parameter-group-binlog-row-image-casing-preserved."""

from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-db-parameter-group-binlog-row-image-casing-preserved"
GROUP = "representation"
SERVICES = ["rds"]

_FAMILY = "mysql8.0"
_PARAM_NAME = "binlog_row_image"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """ModifyDBParameterGroup on a mysql8.0 group stores binlog_row_image with the exact casing
    sent -- 'FULL' and 'full' each round-trip unchanged through DescribeDBParameters(Source=user).
    """
    rds = ctx.client("rds")

    pg_name = ctx.unique_name("sim2real-pg-binlogcasing-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily=_FAMILY,
        Description="sim2real behavioral check",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        _teardown(
            lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name),
            "DBParameterGroupNotFound",
        )
    )

    rds.modify_db_parameter_group(
        DBParameterGroupName=pg_name,
        Parameters=[
            {"ParameterName": _PARAM_NAME, "ParameterValue": "FULL", "ApplyMethod": "immediate"}
        ],
    )
    upper = _wait_user_value(ctx, rds, pg_name, _PARAM_NAME, "FULL")
    assert upper == "FULL", f"stored value after sending 'FULL' was {upper!r}, expected 'FULL'"

    rds.modify_db_parameter_group(
        DBParameterGroupName=pg_name,
        Parameters=[
            {"ParameterName": _PARAM_NAME, "ParameterValue": "full", "ApplyMethod": "immediate"}
        ],
    )
    lower = _wait_user_value(ctx, rds, pg_name, _PARAM_NAME, "full")
    assert lower == "full", f"stored value after sending 'full' was {lower!r}, expected 'full'"

    rds.delete_db_parameter_group(DBParameterGroupName=pg_name)
    code, message = _error(lambda: rds.describe_db_parameter_groups(DBParameterGroupName=pg_name))
    expected = ("DBParameterGroupNotFound", f"DBParameterGroup not found: {pg_name}")
    assert (code, message) == expected, (
        f"describe after delete gave {(code, message)!r}, expected {expected!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_user_value(
    ctx: Any, rds: Any, pg_name: str, param_name: str, want: str, *, timeout_s: float = 30.0
) -> str | None:
    """The parameter's Source='user' ParameterValue, polled until it equals ``want``.

    A freshly modified parameter group can show the prior value for a moment; the poll stops only
    on the asserted value and returns the last one read when the deadline passes.
    """
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    value = None
    while time.monotonic() < deadline:
        param = _describe_parameter(rds, pg_name, param_name)
        value = None if param is None else (param.get("Source"), param.get("ParameterValue"))
        if value == ("user", want):
            return want
        time.sleep(3)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"{param_name} reaching {want!r}: the run budget ended first; not graded"
        )
    return None if value is None else value[1]


def _describe_parameter(rds: Any, pg_name: str, param_name: str) -> dict[str, Any] | None:
    paginator = rds.get_paginator("describe_db_parameters")
    for page in paginator.paginate(DBParameterGroupName=pg_name, Source="user"):
        for p in page["Parameters"]:
            if p["ParameterName"] == param_name:
                return p
    return None


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; AssertionError on success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message") or ""
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
