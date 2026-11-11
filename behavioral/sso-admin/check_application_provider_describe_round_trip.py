"""application-provider-describe-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-provider-describe-round-trip"
GROUP = "state"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A provider ARN returned by ListApplicationProviders is independently resolvable via
    DescribeApplicationProvider, with matching federation protocol, display data and resource
    server config."""

    sso = ctx.client("sso-admin")
    providers = sso.list_application_providers().get("ApplicationProviders", [])
    if not providers:
        raise AssertionError("no built-in application providers are available in this account/partition")

    listed = providers[0]
    described = sso.describe_application_provider(ApplicationProviderArn=listed["ApplicationProviderArn"])

    assert described["ApplicationProviderArn"] == listed["ApplicationProviderArn"], (
        f"describe returned a different ARN: expected {listed['ApplicationProviderArn']!r}, "
        f"got {described['ApplicationProviderArn']!r}"
    )
    assert described["FederationProtocol"] == listed["FederationProtocol"], (
        f"federation protocol mismatch for {listed['ApplicationProviderArn']}: "
        f"list said {listed['FederationProtocol']!r}, describe said {described.get('FederationProtocol')!r}"
    )

    listed_display = listed.get("DisplayData", {})
    described_display = described.get("DisplayData", {})
    assert described_display.get("DisplayName") == listed_display.get("DisplayName"), (
        f"display name mismatch for {listed['ApplicationProviderArn']}: "
        f"list {listed_display.get('DisplayName')!r} vs describe {described_display.get('DisplayName')!r}"
    )
    assert described_display.get("Description") == listed_display.get("Description"), (
        f"description mismatch for {listed['ApplicationProviderArn']}: "
        f"list {listed_display.get('Description')!r} vs describe {described_display.get('Description')!r}"
    )

    if listed.get("ResourceServerConfig"):
        assert described.get("ResourceServerConfig") == listed["ResourceServerConfig"], (
            f"resource server config mismatch for {listed['ApplicationProviderArn']}: "
            f"list {listed['ResourceServerConfig']!r} vs describe {described.get('ResourceServerConfig')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
