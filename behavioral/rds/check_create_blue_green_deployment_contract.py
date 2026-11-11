"""create-blue-green-deployment-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-blue-green-deployment-contract"
GROUP = 'blue_green_deployments'
SERVICES = ['rds']

ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"


def _error_code(fn):
    """Call fn() and return its error code and message; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBlueGreenDeployment with a well-formed Source ARN for a missing DB instance rejects
    with DBInstanceNotFound; a non-ARN Source is rejected with a different code, showing the
    service parses Source rather than returning a canned not-found."""
    rds = ctx.client("rds")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_id = ctx.unique_name("sim2real-behav-dbi-missing-")
    source_arn = f"arn:aws:rds:{ctx.region}:{account}:db:{bogus_id}"
    code, message = _error_code(
        lambda: rds.create_blue_green_deployment(
            BlueGreenDeploymentName=ctx.unique_name("sim2real-behav-bgd-"),
            Source=source_arn,
        )
    )
    assert code == ERR_DB_INSTANCE_NOT_FOUND, f"unexpected error code: {code}"
    assert message == f"Source DB instance [{source_arn}] not found", message

    malformed_code, _malformed_message = _error_code(
        lambda: rds.create_blue_green_deployment(
            BlueGreenDeploymentName=ctx.unique_name("sim2real-behav-bgd-"),
            Source="not-an-arn-at-all",
        )
    )
    assert malformed_code != ERR_DB_INSTANCE_NOT_FOUND, (
        f"a Source value that is not an ARN at all was rejected with the same code "
        f"({malformed_code!r}) as a well-formed-but-missing ARN; the service must be parsing "
        f"the Source shape, not returning a canned not-found for any input"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
