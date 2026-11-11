"""describe-connector-s3-builtin-capabilities."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-connector-s3-builtin-capabilities"
GROUP = "control-plane"
SERVICES = ["appflow"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConnector for the built-in S3 connector reports it as usable source+destination."""
    appflow = ctx.client("appflow")
    resp = appflow.describe_connector(connectorType="S3")
    config = resp["connectorConfiguration"]
    assert config["canUseAsSource"] is True, (
        f"expected S3 canUseAsSource=True, got {config['canUseAsSource']!r}"
    )
    assert config["canUseAsDestination"] is True, (
        f"expected S3 canUseAsDestination=True, got {config['canUseAsDestination']!r}"
    )
    assert config["connectorType"] == "S3", (
        f"expected connectorType='S3', got {config['connectorType']!r}"
    )
    # Built-in connectors are not registered via the Lambda custom-connector
    # provisioning path, so connectorProvisioningType must be absent.
    assert config.get("connectorProvisioningType") is None, (
        f"expected no connectorProvisioningType for a built-in connector, "
        f"got {config.get('connectorProvisioningType')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
