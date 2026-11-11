"""create-receipt-rule-rich-actions-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-receipt-rule-rich-actions-round-trip"
GROUP = "receipt-rules"
SERVICES = ["ses"]


def _require_receipt_region(ctx):
    """Fail outside the regions that support SES email receiving."""
    if ctx.region not in ("us-east-1", "us-west-2", "eu-west-1"):
        raise AssertionError(f"SES email receiving (receipt rules) is unavailable in {ctx.region}")


def _error(fn):
    """Return fn()'s (Error.Code, Error.Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReceiptRule round-trips recipients, ordered actions and a default SNSAction Encoding of
    UTF-8; a rule naming a deleted SNS topic is refused InvalidSnsTopic and leaves no partial rule.
    """
    ses = ctx.client("ses")
    sns = ctx.client("sns")
    _require_receipt_region(ctx)

    rule_set = ctx.unique_name("sim2real-behav-ruleset-rich-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-rich-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    rich_rule = {
        "Name": "rich",
        "Enabled": True,
        "TlsPolicy": "Require",
        "ScanEnabled": True,
        "Recipients": ["probe@example.com", "other@example.org"],
        "Actions": [
            {"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "v1"}},
            {"SNSAction": {"TopicArn": topic_arn}},
            {"StopAction": {"Scope": "RuleSet"}},
        ],
    }
    ses.create_receipt_rule(RuleSetName=rule_set, Rule=rich_rule)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule(RuleSetName=rule_set, RuleName="rich"))

    described = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName="rich")["Rule"]
    assert described["Enabled"] is True, f"expected Enabled True, got {described['Enabled']!r}"
    assert described["TlsPolicy"] == "Require", f"expected TlsPolicy Require, got {described['TlsPolicy']!r}"
    assert described["ScanEnabled"] is True, f"expected ScanEnabled True, got {described['ScanEnabled']!r}"

    # Recipients come back as the submitted set; real AWS sorts them, but no order is documented.
    assert sorted(described["Recipients"]) == sorted(["other@example.org", "probe@example.com"]), (
        f"expected Recipients ['other@example.org', 'probe@example.com'] in any order, got "
        f"{described['Recipients']!r}"
    )

    actions = described["Actions"]
    assert len(actions) == 3, f"expected 3 actions, got {len(actions)}: {actions!r}"
    assert actions[0].get("AddHeaderAction", {}).get("HeaderName") == "X-Sim2Real", (
        f"expected action 0 to be the AddHeaderAction in submitted order, got {actions[0]!r}"
    )
    sns_action = actions[1].get("SNSAction")
    assert sns_action is not None, f"expected action 1 to be the SNSAction in submitted order, got {actions[1]!r}"
    assert sns_action["TopicArn"] == topic_arn, f"expected TopicArn {topic_arn!r}, got {sns_action['TopicArn']!r}"
    # Encoding is omitted on the request; the server stores its default.
    assert sns_action.get("Encoding") == "UTF-8", (
        f"expected the omitted SNSAction.Encoding to default to 'UTF-8', got {sns_action.get('Encoding')!r}"
    )
    assert "StopAction" in actions[2], f"expected action 2 to be the StopAction in submitted order, got {actions[2]!r}"
    assert actions[2]["StopAction"]["Scope"] == "RuleSet", actions[2]

    # A well-formed, account-scoped topic ARN that addresses no real topic.
    stale_topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-stale-topic-"))["TopicArn"]
    sns.delete_topic(TopicArn=stale_topic_arn)

    bad_rule = {
        "Name": "snsneg",
        "Enabled": True,
        "Actions": [{"SNSAction": {"TopicArn": stale_topic_arn}}],
    }
    err = _error(lambda: ses.create_receipt_rule(RuleSetName=rule_set, Rule=bad_rule))
    expected = ("InvalidSnsTopic", f"Could not publish to SNS topic: {stale_topic_arn}")
    assert err == expected, f"expected {expected!r}, got {err!r}"

    names = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]]
    assert names == ["rich"], f"a rejected CreateReceiptRule must not add a rule, got rule set {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
