"""get-connection-reflects-host-association."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-connection-reflects-host-association"
GROUP = "state"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A connection created with a HostArn reports that same HostArn back via GetConnection."""
    cc = ctx.client("codestar-connections")
    host_arn = cc.create_host(
        Name=ctx.unique_name("sim2real-host-"),
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe.example.com",
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["HostArn"]
    ctx.on_cleanup(lambda: _safe_delete_host(cc, host_arn))

    conn_name = ctx.unique_name("sim2real-cn-")[:32]
    conn_arn = cc.create_connection(
        ConnectionName=conn_name,
        HostArn=host_arn,
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn_arn))

    got = cc.get_connection(ConnectionArn=conn_arn)["Connection"]
    assert got["HostArn"] == host_arn, f"expected HostArn {host_arn!r}, got {got['HostArn']!r}"
    assert got["ConnectionStatus"] == "PENDING", (
        f"expected ConnectionStatus 'PENDING', got {got['ConnectionStatus']!r}"
    )
    assert got["ConnectionName"] == conn_name, (
        f"expected ConnectionName {conn_name!r}, got {got['ConnectionName']!r}"
    )


def _safe_delete_connection(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_host(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_host(HostArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
