"""update-receipt-rule-invalid-sns-topic-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-receipt-rule-invalid-sns-topic-rejected"
GROUP = "error-semantics"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateReceiptRule with an SNSAction on a deleted topic fails with InvalidSnsTopic and leaves the
    rule untouched, while an SNSAction on an existing topic is accepted."""
    ses = ctx.client("ses")
    sns = ctx.client("sns")
    rule_set_name = ctx.unique_name("sim2real-ses-rs-")
    rule_name = ctx.unique_name("sim2real-ses-rule-")

    live_topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-ses-live-topic-"),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=live_topic_arn))

    # A created-then-deleted topic gives a well-formed, account-scoped ARN with no topic behind it.
    stale_topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-ses-stale-topic-"))["TopicArn"]
    sns.delete_topic(TopicArn=stale_topic_arn)

    ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set_name))

    base_rule = {
        "Name": rule_name,
        "Enabled": True,
        "TlsPolicy": "Optional",
        "Recipients": [],
        "Actions": [{"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "v1"}}],
        "ScanEnabled": False,
    }
    ses.create_receipt_rule(RuleSetName=rule_set_name, Rule=base_rule)

    live_rule = dict(base_rule)
    live_rule["Actions"] = [{"SNSAction": {"TopicArn": live_topic_arn, "Encoding": "UTF-8"}}]
    ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=live_rule)
    described_live = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name)["Rule"]
    assert described_live["Actions"] == live_rule["Actions"], (
        f"positive-control SNSAction update did not take effect: {described_live['Actions']!r}"
    )

    bad_rule = dict(base_rule)
    bad_rule["Actions"] = [{"SNSAction": {"TopicArn": stale_topic_arn, "Encoding": "UTF-8"}}]

    code = _error_code(
        lambda: ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=bad_rule)
    )
    assert code == ("InvalidSnsTopic", f"Could not publish to SNS topic: {stale_topic_arn}"), (
        f"expected InvalidSnsTopic, got {code!r}"
    )

    described = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name)["Rule"]
    assert described["Actions"] == live_rule["Actions"], (
        f"rejected update mutated the stored rule's actions: {described['Actions']!r}"
    )

    good_rule = dict(base_rule)
    good_rule["Actions"] = [{"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "v2"}}]
    ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=good_rule)
    described2 = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name)["Rule"]
    assert described2["Actions"][0]["AddHeaderAction"]["HeaderValue"] == "v2", (
        "final legitimate update did not take effect"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except Exception as exc:
        error = getattr(exc, "response", {}).get("Error", {})
        if error.get("Code") is None:
            raise
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
