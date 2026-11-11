"""create-connection-without-provider-type-or-host."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-connection-without-provider-type-or-host"
GROUP = "overly-permissive"
SERVICES = ["codestar-connections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnection with neither ProviderType nor HostArn is rejected outright — one
    of the two is mandatory, distinct from providing both (also rejected elsewhere).
    """
    cc = ctx.client("codestar-connections")
    name = ctx.unique_name("sim2real-cn-")[:32]

    try:
        cc.create_connection(ConnectionName=name)
        raise AssertionError("expected CreateConnection to reject a missing ProviderType/HostArn")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ValidationException", exc.response["Error"]["Code"]
        assert exc.response["Error"]["Message"] == "Must specify either HostArn or ProviderType", (
            exc.response["Error"]["Message"]
        )

    # Positive control: supplying ProviderType alone still succeeds.
    resp = cc.create_connection(
        ConnectionName=name,
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, arn))
    got = cc.get_connection(ConnectionArn=arn)["Connection"]
    assert got["ConnectionStatus"] == "PENDING", got["ConnectionStatus"]


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
