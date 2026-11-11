"""cluster-parameter-group-rejects-out-of-range-value."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-parameter-group-rejects-out-of-range-value"
GROUP = 'cluster-parameter-application'
SERVICES = ['neptune']

_FAMILY = 'neptune1.4'
_PARAM = 'neptune_streams_expiry_days'


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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyDBClusterParameterGroup rejects a value outside the documented 1-90 range
    for neptune_streams_expiry_days, leaving the group's value unchanged, while a value
    inside the range is accepted.
    """
    neptune = ctx.client("neptune")
    pg_name = ctx.unique_name("sim2real-behav-neptune-cpg-range-")

    neptune.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name,
        DBParameterGroupFamily=_FAMILY,
        Description="sim2real-probe neptune range-validation parameter group",
    )
    ctx.on_cleanup(_teardown(
        lambda: neptune.delete_db_cluster_parameter_group(DBClusterParameterGroupName=pg_name),
        "DBParameterGroupNotFound",
    ))

    def user_value() -> str | None:
        params = neptune.describe_db_cluster_parameters(
            DBClusterParameterGroupName=pg_name, Source="user"
        )["Parameters"]
        values = {p["ParameterName"]: p["ParameterValue"] for p in params}
        return values.get(_PARAM)

    assert user_value() is None, f"expected no user override yet, saw {user_value()!r}"

    code, message = _error(lambda: neptune.modify_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name,
        Parameters=[{"ParameterName": _PARAM, "ParameterValue": "91", "ApplyMethod": "pending-reboot"}],
    ))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}: {message!r}"
    assert message == f"Value: 91 is outside of range: 1-90 for parameter: {_PARAM}", (
        f"unexpected message {message!r}"
    )
    assert user_value() is None, (
        f"the out-of-range modify must not have taken effect, but saw {user_value()!r}"
    )

    neptune.modify_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name,
        Parameters=[{"ParameterName": _PARAM, "ParameterValue": "45", "ApplyMethod": "pending-reboot"}],
    )
    assert user_value() == "45", f"expected the in-range value 45 to apply, saw {user_value()!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
