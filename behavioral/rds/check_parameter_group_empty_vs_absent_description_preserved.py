"""parameter-group-empty-vs-absent-description-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "parameter-group-empty-vs-absent-description-preserved"
GROUP = "representation"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBParameterGroup rejects an empty Description with InvalidParameterValue and creates no
    group, while a whitespace-only Description and one with surrounding whitespace are each stored and
    read back verbatim."""
    rds = ctx.client("rds")
    family = _pick_parameter_group_family(rds, "mysql")

    # Explicit empty-string Description is rejected, not silently stored as ''.
    empty_name = ctx.unique_name("sim2real-pgdesc-empty-")
    empty_code, empty_message = _error(
        lambda: rds.create_db_parameter_group(
            DBParameterGroupName=empty_name, DBParameterGroupFamily=family, Description=""
        )
    )
    assert empty_code == "InvalidParameterValue", f"unexpected error code {empty_code!r}"
    expected_empty = "The parameter Description must be provided and must not be blank."
    assert empty_message == expected_empty, (
        f"unexpected error message {empty_message!r} != {expected_empty!r}"
    )

    # The rejected attempt did not actually create a parameter group.
    absent_code, absent_message = _error(
        lambda: rds.describe_db_parameter_groups(DBParameterGroupName=empty_name)
    )
    assert absent_code == "DBParameterGroupNotFound", (
        f"unexpected error code {absent_code!r} for supposedly-uncreated group {empty_name!r}"
    )
    expected_absent = f"DBParameterGroup not found: {empty_name}"
    assert absent_message == expected_absent, (
        f"unexpected error message {absent_message!r} != {expected_absent!r}"
    )

    # A whitespace-only Description is technically non-empty -- it is accepted (distinct
    # from the "" rejection above) and preserved exactly, not trimmed to "" server-side.
    blank_name = ctx.unique_name("sim2real-pgdesc-blank-")
    blank_description = "   "
    rds.create_db_parameter_group(
        DBParameterGroupName=blank_name,
        DBParameterGroupFamily=family,
        Description=blank_description,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=blank_name))
    blank_described = rds.describe_db_parameter_groups(DBParameterGroupName=blank_name)[
        "DBParameterGroups"
    ][0]
    assert blank_described["Description"] == blank_description, (
        f"expected whitespace-only Description preserved verbatim as {blank_description!r}, got "
        f"{blank_described['Description']!r}"
    )

    # A non-blank Description WITH surrounding whitespace round-trips exactly -- proving
    # the server doesn't quietly strip() content once it clears the blank-rejection check.
    real_name = ctx.unique_name("sim2real-pgdesc-real-")
    real_description = "  sim2real behavioral test group  "
    rds.create_db_parameter_group(
        DBParameterGroupName=real_name,
        DBParameterGroupFamily=family,
        Description=real_description,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=real_name))

    described = rds.describe_db_parameter_groups(DBParameterGroupName=real_name)[
        "DBParameterGroups"
    ][0]
    assert described["Description"] == real_description, (
        f"expected Description preserved verbatim as {real_description!r}, got "
        f"{described['Description']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _pick_parameter_group_family(rds, engine: str) -> str:
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)["DBEngineVersions"]
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine)["DBEngineVersions"]
    return versions[0]["DBParameterGroupFamily"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
