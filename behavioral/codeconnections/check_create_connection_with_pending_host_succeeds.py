"""create-connection-with-pending-host-succeeds."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-connection-with-pending-host-succeeds"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnection on a PENDING host succeeds: the connection is PENDING, carries the HostArn and is
    listed by ListConnections filtered by that host."""
    cc = ctx.client("codeconnections")
    host_name = ctx.unique_name("sim2real-host-")[:64]
    host_arn = cc.create_host(
        Name=host_name,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe.sim2real-behavioral.example.com",
        Tags=[{"Key": "sim2real", "Value": "audit"}],
    )["HostArn"]
    ctx.on_cleanup(lambda: cc.delete_host(HostArn=host_arn))
    host_status = cc.get_host(HostArn=host_arn)["Status"]
    assert host_status == "PENDING", f"expected host Status=PENDING, got {host_status!r}"

    conn_name = ctx.unique_name("sim2realcc-")[-32:]
    resp = cc.create_connection(
        ConnectionName=conn_name,
        HostArn=host_arn,
        Tags=[{"Key": "sim2real", "Value": "audit"}],
    )
    conn_arn = resp["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    got = cc.get_connection(ConnectionArn=conn_arn)["Connection"]
    assert got["ConnectionStatus"] == "PENDING", (
        f"expected connection ConnectionStatus=PENDING, got {got['ConnectionStatus']!r}"
    )
    assert got["HostArn"] == host_arn, f"expected HostArn={host_arn!r}, got {got['HostArn']!r}"

    filtered = cc.list_connections(HostArnFilter=host_arn)["Connections"]
    filtered_arns = [c["ConnectionArn"] for c in filtered]
    assert conn_arn in filtered_arns, (
        f"expected {conn_arn!r} in ListConnections(HostArnFilter={host_arn!r}), got {filtered_arns!r}"
    )

    # positive control: CreateConnection without a HostArn still succeeds too
    name2 = ctx.unique_name("sim2realcc-")[-32:]
    conn_arn2 = cc.create_connection(
        ConnectionName=name2,
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real", "Value": "audit"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn2))
    status2 = cc.get_connection(ConnectionArn=conn_arn2)["Connection"]["ConnectionStatus"]
    assert status2 == "PENDING", f"expected connection ConnectionStatus=PENDING, got {status2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
