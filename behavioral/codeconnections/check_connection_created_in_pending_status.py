"""connection-created-in-pending-status."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-created-in-pending-status"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnection always returns a connection in PENDING status (the third-party
    handshake can only be completed from the console), never AVAILABLE at creation time."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]
    resp = cc.create_connection(
        ConnectionName=name,
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))

    assert arn.startswith("arn:aws"), f"expected an arn:aws-prefixed ARN, got {arn!r}"
    assert ":connection/" in arn, f"expected a ':connection/' resource segment, got {arn!r}"
    assert "codeconnections" in arn or "codestar-connections" in arn, (
        f"expected the codeconnections/codestar-connections service segment, got {arn!r}"
    )

    got = cc.get_connection(ConnectionArn=arn)["Connection"]
    assert got["ConnectionName"] == name, (
        f"expected ConnectionName {name!r} on the independent GetConnection read, got {got['ConnectionName']!r}"
    )
    assert got["ConnectionArn"] == arn, (
        f"expected ConnectionArn {arn!r} on the independent GetConnection read, got {got['ConnectionArn']!r}"
    )
    assert got["ConnectionStatus"] == "PENDING", (
        "CreateConnection must always leave a connection PENDING (the third-party handshake "
        f"only completes from the console), got ConnectionStatus={got['ConnectionStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
