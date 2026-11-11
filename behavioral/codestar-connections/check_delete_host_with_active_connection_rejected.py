"""delete-host-with-active-connection-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-host-with-active-connection-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-connections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteHost is rejected while a connection still references the host; removing the
    connection first allows the host to be deleted.
    """
    cc = ctx.client("codestar-connections")

    host_arn = cc.create_host(
        Name=ctx.unique_name("sim2real-host-"),
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe.example.com",
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["HostArn"]
    ctx.on_cleanup(lambda: _safe_delete_host(cc, host_arn))

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-cn-")[:32],
        HostArn=host_arn,
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn_arn))

    err = _error(lambda: cc.delete_host(HostArn=host_arn))
    assert err["Code"] == "ResourceUnavailableException", (
        f"expected ResourceUnavailableException deleting a host with an active connection, got {err!r}"
    )
    assert err["Message"] == f"There exist connections for host {host_arn}, host cannot be deleted", (
        err["Message"]
    )

    # effect absent: the host still exists and is describable
    got = cc.get_host(HostArn=host_arn)
    assert got["Name"], f"expected the host to still exist after the rejected delete, got {got!r}"

    # positive control: removing the connection first allows the host to be deleted
    cc.delete_connection(ConnectionArn=conn_arn)
    cc.delete_host(HostArn=host_arn)

    err2 = _error(lambda: cc.get_host(HostArn=host_arn))
    assert err2["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after deleting the host, got {err2!r}"
    )
    assert err2["Message"] == f"No host exists with the ARN: {host_arn}", err2["Message"]


def _error(fn):
    """Call fn(); return its error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
