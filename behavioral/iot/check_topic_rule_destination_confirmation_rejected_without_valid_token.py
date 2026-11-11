"""topic-rule-destination-confirmation-rejected-without-valid-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-rule-destination-confirmation-rejected-without-valid-token"
GROUP = "error-semantics"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A new HTTP topic rule destination is IN_PROGRESS; ConfirmTopicRuleDestination with a bogus
    token fails with InvalidRequestException and leaves it not ENABLED, and another destination
    can still be created IN_PROGRESS."""
    iot = ctx.client("iot")

    dest = iot.create_topic_rule_destination(
        destinationConfiguration={
            "httpUrlConfiguration": {"confirmationUrl": "https://example.com/sim2real-iot-confirm"}
        }
    )["topicRuleDestination"]
    arn = dest["arn"]
    ctx.on_cleanup(lambda: _delete_destination_ignore(iot, arn))
    assert dest["status"] == "IN_PROGRESS", f"expected IN_PROGRESS on creation, got {dest['status']}"

    bogus_token = "sim2real-bogus-token-" + ctx.unique_name("x")
    code, message = _error_code(lambda: iot.confirm_topic_rule_destination(confirmationToken=bogus_token))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Invalid confirmation token.", f"expected 'Invalid confirmation token.', got {message!r}"

    got = iot.get_topic_rule_destination(arn=arn)["topicRuleDestination"]
    assert got["status"] != "ENABLED", f"bogus-token confirmation changed status to {got['status']}"

    dest2 = iot.create_topic_rule_destination(
        destinationConfiguration={
            "httpUrlConfiguration": {"confirmationUrl": "https://example.org/sim2real-iot-confirm2"}
        }
    )["topicRuleDestination"]
    ctx.on_cleanup(lambda: _delete_destination_ignore(iot, dest2["arn"]))
    assert dest2["status"] == "IN_PROGRESS", f"expected IN_PROGRESS on creation, got {dest2['status']}"


def _error_code(fn):
    """Return (code, message) of the ClientError fn() raises; fail loudly if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected confirm_topic_rule_destination to be rejected, but it SUCCEEDED: {result!r}")


def _delete_destination_ignore(iot, arn: str) -> None:
    """Teardown: a missing destination is clean; anything else raises."""
    try:
        iot.delete_topic_rule_destination(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
