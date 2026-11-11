"""list-nodes-summary-invalid-aggregator-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-nodes-summary-invalid-aggregator-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListNodesSummary with a malformed AttributeName fails with ValidationException and the exact message before
    any enablement check, while a well-formed Aggregator fails with UnsupportedOperationException;
    DescribeInstanceInformation answers."""
    ssm = ctx.client("ssm")

    positive_control = ssm.describe_instance_information()
    assert "InstanceInformationList" in positive_control, (
        f"expected DescribeInstanceInformation to succeed as a positive control, got {positive_control}"
    )

    def _call_well_formed():
        ssm.list_nodes_summary(
            Aggregators=[
                {"AggregatorType": "Count", "TypeName": "Instance", "AttributeName": "PlatformType"}
            ]
        )

    well_formed = _error(_call_well_formed)
    well_formed_code = well_formed["Code"]
    assert well_formed_code == "UnsupportedOperationException", (
        f"expected UnsupportedOperationException, got {well_formed!r}"
    )
    expected_well_formed_message = "This is an unsupported operation for this account. You must first enable the Systems Manager integrated experience in your account."
    assert well_formed.get("Message") == expected_well_formed_message, (
        f"expected message {expected_well_formed_message!r}, got {well_formed.get('Message')!r}"
    )

    def _call_malformed():
        ssm.list_nodes_summary(
            Aggregators=[
                {
                    "AggregatorType": "Count",
                    "TypeName": "Instance",
                    "AttributeName": "TotallyBogusAttribute",
                }
            ]
        )

    malformed = _error(_call_malformed)
    malformed_code = malformed["Code"]
    assert malformed_code == "ValidationException", (
        f"expected ValidationException, got {malformed!r}"
    )
    expected_malformed_message = (
        "1 validation error detected: Value 'TotallyBogusAttribute' at "
        "'aggregators.1.member.attributeName' failed to satisfy constraint: Member must satisfy "
        "enum value set: [PlatformVersion, AvailabilityZone, ResourceType, PlatformType, "
        "ExtensionStatus, AgentVersion, Region, SourceType, ExtensionVersion, ExtensionId, "
        "PlatformName]"
    )
    assert malformed.get("Message") == expected_malformed_message, (
        f"expected message {expected_malformed_message!r}, got {malformed.get('Message')!r}"
    )

    assert well_formed_code != malformed_code, (
        "expected shape validation (malformed AttributeName) to be distinct from "
        "the account-enablement gate (well-formed Aggregator)"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected success
    raises, so an emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, the call unexpectedly succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
