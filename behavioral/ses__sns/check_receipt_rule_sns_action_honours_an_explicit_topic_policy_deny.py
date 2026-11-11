"""receipt-rule-sns-action-honours-an-explicit-topic-policy-deny."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-sns-action-honours-an-explicit-topic-policy-deny"
GROUP = "overly-permissive"
SERVICES = ["ses", "sns"]

# SES email receiving is region-pinned (inbound MX endpoints exist only in a subset of regions:
# https://docs.aws.amazon.com/general/latest/gr/ses.html#ses_inbound_endpoints). Both clients are
# PINNED to a receiving region, because "Except for Amazon S3 buckets, the AWS resources that you
# use to receive email must be in the same region as your Amazon SES endpoint" — so the SNS topic
# has to share it. This is a transport pin, never a guard on an assertion.
_RECEIVING_REGIONS = ("us-east-1", "us-west-2", "eu-west-1")
_DEFAULT_RECEIVING_REGION = "us-east-1"
_DENY_SID = "sim2real-deny-ses-publish"


def _client_error(fn) -> dict:
    """Return the botocore Error dict; an unexpected SUCCESS raises rather than returning a falsy
    sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll_call(fn, *, timeout_s, interval_s, description):
    """Call fn() until it stops raising ClientError; RAISE on the deadline (never return the last
    failure, never a bare sleep as the barrier)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as exc:
            last = exc.response.get("Error", {})
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not succeed within {timeout_s}s; last refusal {last!r}"
            )
        time.sleep(interval_s)


def _with_ses_deny(policy_document: str, topic_arn: str) -> str:
    """The topic's own default policy plus ONE explicit Deny of sns:Publish for the SES service
    principal. Explicit deny is terminal in AWS policy evaluation, so a target that evaluates the
    document at all cannot reach any other answer."""
    document = json.loads(policy_document)
    document["Statement"] = list(document["Statement"]) + [
        {
            "Sid": _DENY_SID,
            "Effect": "Deny",
            "Principal": {"Service": "ses.amazonaws.com"},
            "Action": "sns:Publish",
            "Resource": topic_arn,
        }
    ]
    return json.dumps(document)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SES's CreateReceiptRule SNSAction check evaluates the topic policy: an explicit Deny of
    sns:Publish for ses.amazonaws.com is refused with InvalidSnsTopic, removing it restores
    acceptance, and SES never edits the topic policy or subscribes anything to the topic.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    recv_region = (
        ctx.region if ctx.region in _RECEIVING_REGIONS else _DEFAULT_RECEIVING_REGION
    )
    ses = ctx.client("ses", region=recv_region)
    sns = ctx.client("sns", region=recv_region)

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-ses-sns-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    assert topic_arn.startswith(f"arn:aws:sns:{recv_region}:{account}:"), (
        f"the topic must live in the account and the SES receiving region; CreateTopic "
        f"returned {topic_arn!r}"
    )
    baseline_policy = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"]
    assert "ses.amazonaws.com" not in baseline_policy, (
        f"setup precondition: the fresh topic must carry only SNS's default policy with no SES "
        f"statement, so the only thing broken in the negative leg is the deny; got "
        f"{baseline_policy!r}"
    )

    rule_set = ctx.unique_name("sim2real-behav-ses-rs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))
    rule = "sns-notify"

    def _create_rule():
        return ses.create_receipt_rule(
            RuleSetName=rule_set,
            Rule={
                "Name": rule,
                "Enabled": True,
                "ScanEnabled": False,
                "Actions": [{"SNSAction": {"TopicArn": topic_arn, "Encoding": "UTF-8"}}],
            },
        )

    # --- Beat 1, positive control: with the default policy, the rule is accepted.
    _create_rule()
    described = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName=rule)["Rule"]
    assert described["Actions"][0]["SNSAction"]["TopicArn"] == topic_arn, (
        f"the accepted rule must name the topic; DescribeReceiptRule returned "
        f"{described['Actions'][0]!r}"
    )
    ses.delete_receipt_rule(RuleSetName=rule_set, RuleName=rule)
    assert rule not in [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]
    ], "the control rule must be gone before the negative leg reuses its name"

    # --- Beat 2, break exactly one thing: one explicit Deny, appended to the topic's own policy.
    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=_with_ses_deny(baseline_policy, topic_arn),
    )
    denied_policy = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"]
    denied_sids = [s["Sid"] for s in json.loads(denied_policy)["Statement"]]
    assert _DENY_SID in denied_sids, (
        f"the deny must be observably stored at the consumer before anything is concluded from its "
        f"effect; GetTopicAttributes reported statement ids {denied_sids!r}"
    )

    refused = _client_error(_create_rule)
    assert refused.get("Code") == "InvalidSnsTopic", (
        f"an SNSAction naming a topic whose policy explicitly DENIES sns:Publish to "
        f"ses.amazonaws.com must be refused with InvalidSnsTopic; got {refused.get('Code')!r}: "
        f"{refused.get('Message')!r}"
    )
    assert refused.get("Message") == f"Could not publish to SNS topic: {topic_arn}", (
        f"the InvalidSnsTopic refusal must name the denied topic {topic_arn!r}; got "
        f"{refused.get('Message')!r}"
    )

    # --- Beat 2b, consumer-side positive control: the deny is principal-scoped, so the topic itself
    #     is healthy and the caller can still publish. Without this, "the deny blocked SES" cannot
    #     be told apart from "the topic became unusable".
    published = sns.publish(
        TopicArn=topic_arn,
        Subject="sim2real ses-sns deny probe",
        Message="the caller must still be able to publish while SES is denied",
    )
    assert published.get("MessageId"), (
        f"the topic must remain publishable by the caller while SES is denied — otherwise the "
        f"refusal above is about the topic, not about SES; Publish returned {published!r}"
    )

    # --- Beat 3, effect absent by an independent read at the producer.
    rules_now = [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]
    ]
    assert rules_now == [], (
        f"the refused CreateReceiptRule must persist nothing; DescribeReceiptRuleSet lists "
        f"{rules_now!r}"
    )

    # --- Beat 4, restore: put the topic's original policy back, byte for byte.
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=baseline_policy
    )

    # --- Beat 5: the IDENTICAL call now succeeds; polled because the policy change propagates.
    _poll_call(
        _create_rule,
        timeout_s=180,
        interval_s=10,
        description="CreateReceiptRule accepts the SNSAction again once the explicit deny is gone",
    )

    # --- Beat 6, terminal independent reads AT THE CONSUMER: the topic's policy is exactly what
    #     this check last wrote (SES granted itself nothing) and nothing was subscribed to it. Both
    #     reads are at SNS, through operations SES never called.
    final_attributes = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert json.loads(final_attributes["Policy"]) == json.loads(baseline_policy), (
        f"SES must not add statements to the topic policy — the API path leaves that to the caller, "
        f"unlike the console. Expected the restored baseline, got {final_attributes['Policy']!r}"
    )
    subscriptions = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    assert subscriptions == [], (
        f"creating a receipt rule must not subscribe anything to the topic; "
        f"ListSubscriptionsByTopic returned {subscriptions!r}"
    )
    assert final_attributes["TopicArn"] == topic_arn, (
        f"the consumer must still report the same topic; got {final_attributes['TopicArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
