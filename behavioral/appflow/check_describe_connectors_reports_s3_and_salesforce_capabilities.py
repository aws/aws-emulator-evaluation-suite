"""describe-connectors-reports-s3-and-salesforce-capabilities."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-connectors-reports-s3-and-salesforce-capabilities"
GROUP = "control-plane"
SERVICES = ["appflow"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConnectors (plural, vended connectors) reports both S3 and Salesforce
    with the connector-level capabilities documented for each: S3 is usable as both a
    source and a destination, Salesforce supports S3 as a destination connector."""
    appflow = ctx.client("appflow")
    resp = appflow.describe_connectors(connectorTypes=["S3", "Salesforce"])
    configs = resp["connectorConfigurations"]
    assert "S3" in configs and "Salesforce" in configs, (
        f"expected connectorConfigurations to contain S3 and Salesforce, got keys {sorted(configs)}"
    )
    s3_cfg = configs["S3"]
    sf_cfg = configs["Salesforce"]
    assert s3_cfg["canUseAsSource"] is True, (
        f"expected S3 canUseAsSource=True, got {s3_cfg['canUseAsSource']!r}"
    )
    assert s3_cfg["canUseAsDestination"] is True, (
        f"expected S3 canUseAsDestination=True, got {s3_cfg['canUseAsDestination']!r}"
    )
    assert sf_cfg["canUseAsSource"] is True, (
        f"expected Salesforce canUseAsSource=True, got {sf_cfg['canUseAsSource']!r}"
    )
    assert "S3" in sf_cfg["supportedDestinationConnectors"], (
        "expected S3 in Salesforce supportedDestinationConnectors, got "
        f"{sf_cfg['supportedDestinationConnectors']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
