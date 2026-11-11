"""delete-connection-removes-resource-and-rejects-repeat."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-connection-removes-resource-and-rejects-repeat"
GROUP = "state"
SERVICES = ["codestar-connections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a connection removes it permanently; a repeat delete is rejected, not idempotent."""
    cc = ctx.client("codestar-connections")
    name = ctx.unique_name("sim2real-cn-")[:32]
    arn = cc.create_connection(
        ConnectionName=name,
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, arn))

    # sanity: it exists before deletion
    cc.get_connection(ConnectionArn=arn)

    cc.delete_connection(ConnectionArn=arn)

    err = _error(lambda: cc.get_connection(ConnectionArn=arn))
    assert err["Code"] == "ResourceNotFoundException", (
        f"GetConnection after delete: expected ResourceNotFoundException, got {err!r}"
    )
    assert err["Message"] == "No connection exists with the ARN", err["Message"]

    err2 = _error(lambda: cc.delete_connection(ConnectionArn=arn))
    assert err2["Code"] == "ResourceNotFoundException", (
        f"repeat DeleteConnection: expected ResourceNotFoundException, got {err2!r}"
    )
    assert err2["Message"] == "No connection exists with the ARN", err2["Message"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_connection(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
