"""modify-cluster-parameter-invalid-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cluster-parameter-invalid-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-rds-cpg"},
]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBClusterParameterGroup must reject a ParameterValue outside the parameter's
    AllowedValues (e.g. a non-boolean string for a boolean parameter) rather than silently
    accepting and storing an engine-incompatible value."""
    rds = ctx.client("rds")

    # Discover the current default aurora-postgresql parameter group family rather than
    # hardcoding one, so the check keeps working as AWS retires old major versions.
    versions = rds.describe_db_engine_versions(Engine="aurora-postgresql", DefaultOnly=True)[
        "DBEngineVersions"
    ]
    if not versions:
        versions = rds.describe_db_engine_versions(Engine="aurora-postgresql")["DBEngineVersions"]
    family = versions[0]["DBParameterGroupFamily"]

    pg_name = ctx.unique_name("sim2real-rds-cpg-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name,
        DBParameterGroupFamily=family,
        Description="sim2real invalid-parameter-value negative test",
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster_parameter_group(ctx, pg_name))

    enum_param, valid_value = _find_enum_modifiable_param(rds, pg_name)
    if enum_param is None:
        raise AssertionError(
            f"no boolean, modifiable, value-resolvable parameter found in family {family!r} "
            "to exercise the invalid-value rejection"
        )

    # Break exactly one thing: a ParameterValue that cannot possibly be a member of the
    # parameter's AllowedValues.
    bogus_value = "sim2real-not-a-valid-value-xyz"
    err = _client_error(
        lambda: rds.modify_db_cluster_parameter_group(
            DBClusterParameterGroupName=pg_name,
            Parameters=[
                {
                    "ParameterName": enum_param,
                    "ParameterValue": bogus_value,
                    "ApplyMethod": "pending-reboot",
                }
            ],
        )
    )
    assert err.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {err.get('Code')!r}"
    )
    expected = f"Invalid boolean value: {bogus_value}"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # Effect absent: the parameter must still be unmodified (engine-default), not overridden with
    # the bogus value.
    after_reject = _param_by_name(rds, pg_name, enum_param)
    assert after_reject is not None and after_reject["Source"] != "user", (
        f"parameter should not have been overridden by a rejected invalid value, "
        f"observed Source={after_reject.get('Source')!r}"
    )

    # Positive control: the identical parameter, given a legitimate value from AllowedValues,
    # succeeds and is recorded against the parameter group.
    resp = rds.modify_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name,
        Parameters=[
            {"ParameterName": enum_param, "ParameterValue": valid_value, "ApplyMethod": "pending-reboot"}
        ],
    )
    assert resp["DBClusterParameterGroupName"] == pg_name, (
        f"expected modify response to name the target parameter group {pg_name!r}, "
        f"got {resp.get('DBClusterParameterGroupName')!r}"
    )

    after_accept = _param_by_name(rds, pg_name, enum_param)
    assert after_accept is not None and after_accept["Source"] == "user", (
        f"pending-reboot apply of a valid value should have been recorded, "
        f"observed Source={after_accept.get('Source')!r}"
    )

    # Deleted in the body, not only in cleanup, so a mutation against the dead name can be asserted
    # to fail with the specific not-found code.
    rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=pg_name)

    list_err = _client_error(
        lambda: rds.describe_db_cluster_parameters(DBClusterParameterGroupName=pg_name)
    )
    assert list_err.get("Code") == "DBParameterGroupNotFound", (
        f"deleted cluster parameter group should be gone on an independent read, "
        f"expected DBParameterGroupNotFound, got {list_err.get('Code')!r}"
    )
    expected_list = f"DBClusterParameterGroup not found: {pg_name}"
    assert list_err.get("Message") == expected_list, (
        f"expected message {expected_list!r}, got {list_err.get('Message')!r}"
    )

    modify_err = _client_error(
        lambda: rds.modify_db_cluster_parameter_group(
            DBClusterParameterGroupName=pg_name,
            Parameters=[
                {"ParameterName": enum_param, "ParameterValue": valid_value, "ApplyMethod": "pending-reboot"}
            ],
        )
    )
    assert modify_err.get("Code") == "DBParameterGroupNotFound", (
        f"a mutation against the deleted cluster parameter group should fail as not-found, "
        f"expected DBParameterGroupNotFound, got {modify_err.get('Code')!r}"
    )
    assert modify_err.get("Message") == "Parameter group does not exist", (
        f"expected message 'Parameter group does not exist', got {modify_err.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, so accepting
    input AWS refuses is reported as such rather than as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _all_cluster_parameters(rds, pg_name):
    params = []
    paginator = rds.get_paginator("describe_db_cluster_parameters")
    for page in paginator.paginate(DBClusterParameterGroupName=pg_name):
        params.extend(page["Parameters"])
    return params


def _param_by_name(rds, pg_name, name):
    for p in _all_cluster_parameters(rds, pg_name):
        if p["ParameterName"] == name:
            return p
    return None


def _resolve_value(param):
    if param.get("ParameterValue"):
        return param["ParameterValue"]
    allowed = param.get("AllowedValues")
    if not allowed:
        return None
    if "," in allowed:
        return allowed.split(",")[0]
    if "-" in allowed and allowed.replace("-", "").replace(".", "").isdigit():
        return allowed.split("-")[0]
    return allowed


def _find_enum_modifiable_param(rds, pg_name):
    """Find a modifiable parameter whose AllowedValues is a small, closed set, so an out-of-set
    value is unambiguously invalid."""
    for p in _all_cluster_parameters(rds, pg_name):
        if not p.get("IsModifiable") or p.get("DataType") != "boolean":
            continue
        allowed = p.get("AllowedValues")
        if not allowed:
            continue
        # Boolean-style ("0,1" / "true,false") or a short comma-separated enum -- reject any
        # AllowedValues that looks like a numeric range (contains a bare "-" between digits),
        # since those accept arbitrary values inside the range.
        if "," not in allowed:
            continue
        options = allowed.split(",")
        if len(options) > 20:
            continue
        return p["ParameterName"], options[0]
    return None, None


def _safe_delete_cluster_parameter_group(ctx, name) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DBClusterParameterGroupNotFound",
            "DBParameterGroupNotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
