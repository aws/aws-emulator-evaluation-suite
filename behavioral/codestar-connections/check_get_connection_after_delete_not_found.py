"""get-connection-after-delete-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-connection-after-delete-not-found"
GROUP = "lifecycle"
SERVICES = ["codestar-connections"]


def _error(fn):
    """Call fn(); return its error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteConnection, GetConnection on that ARN is ResourceNotFoundException.

    A sibling connection left untouched must still be readable, proving the
    deletion is scoped to the single target ARN and not a wholesale failure.
    """
    csc = ctx.client("codestar-connections")
    sim2real_tags = [{"Key": "sim2real-env", "Value": "test"}]

    target_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-tgt-"),
        ProviderType="GitHub",
        Tags=sim2real_tags,
    )["ConnectionArn"]
    control_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-ctl-"),
        ProviderType="GitHub",
        Tags=sim2real_tags,
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=control_arn))

    csc.delete_connection(ConnectionArn=target_arn)

    err = _error(lambda: csc.get_connection(ConnectionArn=target_arn))
    assert err["Code"] == "ResourceNotFoundException", err
    assert err["Message"] == "No connection exists with the ARN", err["Message"]

    control = csc.get_connection(ConnectionArn=control_arn)["Connection"]
    assert control["ConnectionArn"] == control_arn, control.get("ConnectionArn")
    assert control["ConnectionStatus"] == "PENDING", control.get("ConnectionStatus")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
