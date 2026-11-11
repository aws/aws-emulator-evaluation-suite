"""connection-created-in-pending-status."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-created-in-pending-status"
GROUP = "lifecycle"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A GitHub connection created through the API reads back from GetConnection with its name, provider and ARN
    and in PENDING status, since only the console handshake makes it AVAILABLE.
    """
    csc = ctx.client("codestar-connections")
    name = ctx.unique_name("sim2real-behav-conn-")
    tag_set = [{"Key": "sim2real-env", "Value": "test"}]
    arn = csc.create_connection(ConnectionName=name, ProviderType="GitHub", Tags=tag_set)[
        "ConnectionArn"
    ]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=arn))

    conn = csc.get_connection(ConnectionArn=arn)["Connection"]
    assert conn["ConnectionName"] == name, f"expected ConnectionName {name}, got {conn['ConnectionName']}"
    assert conn["ProviderType"] == "GitHub", f"expected ProviderType GitHub, got {conn['ProviderType']}"
    assert conn["ConnectionArn"] == arn, f"expected ConnectionArn {arn}, got {conn['ConnectionArn']}"
    assert conn["ConnectionStatus"] == "PENDING", (
        f"expected ConnectionStatus PENDING, got {conn['ConnectionStatus']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
