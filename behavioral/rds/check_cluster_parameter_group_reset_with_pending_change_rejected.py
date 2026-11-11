"""cluster-parameter-group-reset-with-pending-change-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-parameter-group-reset-with-pending-change-rejected"
GROUP = "state-machine"
SERVICES = ["rds"]

#: The code ``_outcome`` reports for a call the target accepted.
_ACCEPTED = "<accepted>"

#: Modify-then-reset rounds tried before the check gives up on observing the pending window.
_ATTEMPTS = 5
_EXPECTED = "Cannot reset the parameter group because the parameter 'max_connections' has pending changes."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResetDBClusterParameterGroup sent while a just-modified parameter still has pending changes is
    refused with InvalidDBParameterGroupState and its exact message, and the modified value survives."""
    rds = ctx.client("rds")
    group = ctx.unique_name("sim2real-rds-cpgr-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=group, DBParameterGroupFamily="aurora-mysql8.0",
        Description="cluster parameter group reset while a change is pending",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _drop(rds, group))

    refused = False
    accepted = 0
    for _ in range(_ATTEMPTS):
        rds.modify_db_cluster_parameter_group(
            DBClusterParameterGroupName=group,
            Parameters=[{"ParameterName": "max_connections", "ParameterValue": "300",
                         "ApplyMethod": "pending-reboot"}],
        )
        code, message = _outcome(lambda: rds.reset_db_cluster_parameter_group(
            DBClusterParameterGroupName=group, ResetAllParameters=True))
        if code == _ACCEPTED:
            accepted += 1
            continue
        assert (code, message) == ("InvalidDBParameterGroupState", _EXPECTED), (
            f"a reset right after the modify answered {code!r} {message!r}; expected "
            f"InvalidDBParameterGroupState {_EXPECTED!r}"
        )
        refused = True
        break
    assert refused, f"the reset right after a modify was accepted all {accepted} times; AWS refuses it"

    params = rds.describe_db_cluster_parameters(
        DBClusterParameterGroupName=group, Source="user")["Parameters"]
    got = [(p["ParameterName"], p.get("ParameterValue"), p.get("ApplyMethod")) for p in params]
    assert got == [("max_connections", "300", "pending-reboot")], (
        f"after the refused reset the user parameters are {got!r}, expected max_connections=300"
    )


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, repr of the answer) when the
    target accepts the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


def _drop(rds, group: str) -> None:
    try:
        rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBParameterGroupNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
