"""connection-reflects-provider-type-without-host."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-reflects-provider-type-without-host"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Bitbucket connection created without a HostArn reads back with ProviderType Bitbucket, status
    PENDING and no HostArn field."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]
    arn = cc.create_connection(
        ConnectionName=name,
        ProviderType="Bitbucket",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))

    got = cc.get_connection(ConnectionArn=arn)["Connection"]
    assert got["ProviderType"] == "Bitbucket", f"expected Bitbucket, got {got.get('ProviderType')}"
    assert got["ConnectionStatus"] == "PENDING", f"expected PENDING, got {got.get('ConnectionStatus')}"
    assert "HostArn" not in got, f"expected no HostArn for a cloud provider, got {got.get('HostArn')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
