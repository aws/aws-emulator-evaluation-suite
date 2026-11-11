"""e2e-topic-rule-destination-confirmation-flow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-topic-rule-destination-confirmation-flow"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new HTTP topic rule destination is IN_PROGRESS; a bogus confirmation token
    fails with InvalidRequestException and its exact message and leaves it IN_PROGRESS,
    and a topic rule can still use its URL."""
    iot = ctx.client("iot")

    marker = ctx.unique_name("sim2real-trd-")
    confirmation_url = f"https://{marker}.example.com/confirm"

    created = iot.create_topic_rule_destination(
        destinationConfiguration={"httpUrlConfiguration": {"confirmationUrl": confirmation_url}}
    )["topicRuleDestination"]
    destination_arn = created["arn"]
    assert created["status"] == "IN_PROGRESS", (
        f"expected a freshly created HTTP destination to start IN_PROGRESS, got {created['status']!r}"
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule_destination(arn=destination_arn))

    fetched = iot.get_topic_rule_destination(arn=destination_arn)["topicRuleDestination"]
    assert fetched["status"] == "IN_PROGRESS", (
        f"expected an independent read to confirm IN_PROGRESS, got {fetched['status']!r}"
    )

    code, message = _error_code(
        lambda: iot.confirm_topic_rule_destination(confirmationToken="not-a-real-confirmation-token")
    )
    assert code == "InvalidRequestException", (
        f"expected a bogus confirmation token to be rejected as InvalidRequestException, got {code!r}"
    )
    expected = "Invalid confirmation token."
    assert message == expected, f"ConfirmTopicRuleDestination message {message!r} != {expected!r}"

    still_pending = iot.get_topic_rule_destination(arn=destination_arn)["topicRuleDestination"]
    assert still_pending["status"] == "IN_PROGRESS", (
        "destination status changed even though confirmation was rejected"
    )

    rule_name = ctx.unique_name("sim2real_trd_rule_").replace("-", "_")
    action_url = confirmation_url + "/publish"
    iot.create_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            "sql": f"SELECT * FROM 'sim2real/trd/{marker}'",
            "ruleDisabled": False,
            "actions": [{"http": {"url": action_url, "confirmationUrl": confirmation_url}}],
        },
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))

    rule = iot.get_topic_rule(ruleName=rule_name)["rule"]
    assert rule["actions"][0]["http"]["url"] == action_url, (
        f"expected the persisted rule's HTTP action url to round-trip as {action_url!r}, "
        f"got {rule['actions'][0]['http'].get('url')!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
