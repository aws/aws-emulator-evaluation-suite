"""modify-db-parameter-group-invalid-value-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-db-parameter-group-invalid-value-rejected"
GROUP = "representation"
SERVICES = ["rds"]

_PARAM_NAME = "log_statement"
_INVALID_VALUE = "not_a_valid_enum_value"
_VALID_VALUE = "ddl"
_FAMILY = "postgres16"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """ModifyDBParameterGroup with a value outside log_statement's allowed set is rejected with
    InvalidParameterValue and leaves the value and source unchanged, an allowed value is stored with
    source 'user', and the deleted group answers DBParameterGroupNotFound."""
    rds = ctx.client("rds")

    family = _FAMILY

    pg_name = ctx.unique_name("sim2real-pg-invalidval-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily=family,
        Description="sim2real behavioral check",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _drop_parameter_group(rds, pg_name))

    baseline = _describe_parameter(rds, pg_name, _PARAM_NAME)
    assert baseline is not None, f"{_PARAM_NAME} is not listed in the new {family} parameter group"
    baseline_value = baseline.get("ParameterValue")
    baseline_source = baseline.get("Source")

    # Break exactly one thing: a value outside the enum domain.
    code, status, message = _error(
        lambda: rds.modify_db_parameter_group(
            DBParameterGroupName=pg_name,
            Parameters=[{"ParameterName": _PARAM_NAME, "ParameterValue": _INVALID_VALUE, "ApplyMethod": "immediate"}],
        )
    )
    assert (code, status) == ("InvalidParameterValue", 400), (
        f"expected ('InvalidParameterValue', 400), got ({code!r}, {status})"
    )
    expected_message = f"Invalid parameter value: not_a_valid_enum_value for: {baseline['ParameterName']} allowed values are: {baseline['AllowedValues']}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Effect absent: the parameter is still listed with exactly its pre-refusal value and source.
    after_invalid = _describe_parameter(rds, pg_name, _PARAM_NAME)
    assert after_invalid is not None, (
        f"{_PARAM_NAME} is no longer listed after the refused modification"
    )
    assert after_invalid.get("ParameterValue") == baseline_value, (
        f"parameter value changed despite the refused modification: "
        f"{after_invalid.get('ParameterValue')!r} != {baseline_value!r}"
    )
    assert after_invalid.get("Source") == baseline_source, (
        f"parameter Source changed despite the refused modification: "
        f"{after_invalid.get('Source')!r} != {baseline_source!r}"
    )

    # Positive control: a value inside the allowed domain is accepted.
    rds.modify_db_parameter_group(
        DBParameterGroupName=pg_name,
        Parameters=[{"ParameterName": _PARAM_NAME, "ParameterValue": _VALID_VALUE, "ApplyMethod": "immediate"}],
    )
    # Source propagation on a freshly modified parameter group can lag very slightly
    # behind the ModifyDBParameterGroup response; poll briefly to a stable condition.
    after_valid = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        after_valid = _describe_parameter(rds, pg_name, _PARAM_NAME)
        if after_valid is not None and after_valid.get("Source") == "user":
            break
        time.sleep(3)
    assert after_valid is not None
    assert after_valid.get("ParameterValue") == _VALID_VALUE, (
        f"valid enum value was not accepted: value={after_valid.get('ParameterValue')!r}"
    )
    got_source = after_valid.get("Source")
    msg = "Source did not flip to 'user' after accepted modify: got=" + repr(got_source)
    assert got_source == "user", msg

    # Delete the group and prove it gone and unusable.
    rds.delete_db_parameter_group(DBParameterGroupName=pg_name)
    code, status, message = _error(
        lambda: rds.describe_db_parameter_groups(DBParameterGroupName=pg_name)
    )
    assert (code, status) == ("DBParameterGroupNotFound", 404), (
        f"describe deleted group: expected ('DBParameterGroupNotFound', 404), got ({code!r}, {status})"
    )
    expected_message = f"DBParameterGroup not found: {pg_name}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    listed = [
        g["DBParameterGroupName"]
        for page in rds.get_paginator("describe_db_parameter_groups").paginate()
        for g in page["DBParameterGroups"]
    ]
    assert pg_name not in listed, "DescribeDBParameterGroups still lists the deleted group"
    code, status, message = _error(
        lambda: rds.modify_db_parameter_group(
            DBParameterGroupName=pg_name,
            Parameters=[{"ParameterName": _PARAM_NAME, "ParameterValue": _VALID_VALUE, "ApplyMethod": "immediate"}],
        )
    )
    assert (code, status) == ("DBParameterGroupNotFound", 404), (
        f"modify deleted group: expected ('DBParameterGroupNotFound', 404), got ({code!r}, {status})"
    )
    expected_message = f"DBParameterGroup not found: {pg_name}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, int, str]:
    """(code, HTTP status, message) of the ClientError fn() raises; AssertionError on success."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response["ResponseMetadata"]["HTTPStatusCode"],
            exc.response["Error"].get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _drop_parameter_group(rds: Any, pg_name: str) -> None:
    """Teardown; a group the check already deleted is fine."""
    try:
        rds.delete_db_parameter_group(DBParameterGroupName=pg_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBParameterGroupNotFound":
            raise


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
