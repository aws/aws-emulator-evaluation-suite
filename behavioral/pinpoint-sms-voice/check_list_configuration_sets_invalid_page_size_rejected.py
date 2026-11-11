"""list-configuration-sets-invalid-page-size-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-configuration-sets-invalid-page-size-rejected"
GROUP = "error-semantics"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConfigurationSets rejects a non-numeric PageSize (a string in the model, so it reaches the
    service) with BadRequestException and no message, while PageSize "5" succeeds."""
    client = ctx.client("pinpoint-sms-voice")

    try:
        client.list_configuration_sets(PageSize="not-a-number")
        raise AssertionError(
            "ListConfigurationSets unexpectedly succeeded with a non-numeric PageSize"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "BadRequestException", (
            f"expected a validation-style error, got {code!r}"
        )
        # The service answers this refusal without a message.
        message = e.response["Error"].get("Message")
        assert message is None, f"expected no message, got {message!r}"

    # a syntactically valid call succeeds and does not require any write permission
    resp = client.list_configuration_sets(PageSize="5")
    assert "ConfigurationSets" in resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
