"""topic-delivery-policy-computes-effective-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "topic-delivery-policy-computes-effective-policy"
GROUP = 'policy-and-tags'
SERVICES = ['sns']

def _create_topic(client, ctx, name, attributes=None):
    """CreateTopic (tagged) and register DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {
        "Name": name,
        "Tags": [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    }
    if attributes:
        kwargs["Attributes"] = attributes
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn


def _poll(fn, pred, *, timeout_s, interval_s, what):
    """Poll fn() until pred(val); raise AssertionError on deadline miss."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: condition not met within {timeout_s}s, last value {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _topic_attrs(client, topic_arn):
    return client.get_topic_attributes(TopicArn=topic_arn)["Attributes"]


def _err(fn):
    """Call fn(); return the error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A topic DeliveryPolicy is validated synchronously and merged over the documented defaults into
    a computed EffectiveDeliveryPolicy; rejected writes leave both attributes unchanged.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/sns-message-delivery-retries.html
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-delpol-"))

    # Baseline: EffectiveDeliveryPolicy exists before any DeliveryPolicy is set, because it
    # is computed from defaults rather than stored.
    base = _topic_attrs(sns, topic_arn)
    assert "EffectiveDeliveryPolicy" in base, (
        "EffectiveDeliveryPolicy is computed from account defaults and must be present on a "
        f"topic with no DeliveryPolicy set; got {sorted(base)}"
    )
    baseline_effective = json.loads(base["EffectiveDeliveryPolicy"])
    assert "http" in baseline_effective, (
        f"expected the default EffectiveDeliveryPolicy to carry an 'http' section, got {baseline_effective}"
    )
    baseline_retry = baseline_effective["http"].get("defaultHealthyRetryPolicy", {})
    # SNS's documented, account-independent default HTTP retry policy.
    assert baseline_retry.get("numRetries") == 3, (
        f"expected the default numRetries to be 3, got {baseline_retry!r}"
    )
    assert baseline_retry.get("minDelayTarget") == 20, (
        f"expected the default minDelayTarget to be 20, got {baseline_retry!r}"
    )
    assert baseline_retry.get("maxDelayTarget") == 20, (
        f"expected the default maxDelayTarget to be 20, got {baseline_retry!r}"
    )
    assert baseline_retry.get("backoffFunction") == "linear", (
        f"expected the default backoffFunction to be 'linear', got {baseline_retry!r}"
    )
    baseline_retries = baseline_retry.get("numRetries")

    # Set a real DeliveryPolicy and require the computed view to follow it.
    policy = {
        "http": {
            "defaultHealthyRetryPolicy": {
                "minDelayTarget": 5,
                "maxDelayTarget": 60,
                "numRetries": 7,
                "numMaxDelayRetries": 2,
                "numNoDelayRetries": 0,
                "numMinDelayRetries": 1,
                "backoffFunction": "exponential",
            },
            "disableSubscriptionOverrides": False,
        }
    }
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="DeliveryPolicy", AttributeValue=json.dumps(policy)
    )
    attrs = _poll(
        lambda: _topic_attrs(sns, topic_arn),
        lambda a: a.get("DeliveryPolicy"),
        timeout_s=30.0,
        interval_s=2.0,
        what="DeliveryPolicy becomes readable after SetTopicAttributes",
    )
    stored = json.loads(attrs["DeliveryPolicy"])
    assert stored["http"]["defaultHealthyRetryPolicy"]["numRetries"] == 7, (
        f"expected the stored DeliveryPolicy to round-trip numRetries=7, got {stored}"
    )
    assert stored["http"]["defaultHealthyRetryPolicy"]["backoffFunction"] == "exponential", (
        f"expected backoffFunction to round-trip, got {stored}"
    )

    effective = json.loads(attrs["EffectiveDeliveryPolicy"])
    assert effective["http"]["defaultHealthyRetryPolicy"]["numRetries"] == 7, (
        "EffectiveDeliveryPolicy must be recomputed from the new DeliveryPolicy, not left "
        f"at the account default of {baseline_retries}; got {effective}"
    )
    assert effective["http"]["defaultHealthyRetryPolicy"]["minDelayTarget"] == 5, (
        f"expected the overridden minDelayTarget to appear in the effective policy, got {effective}"
    )
    # The effective policy is a MERGE, not a copy: keys the override omits must still be
    # populated from the defaults. `disableSubscriptionOverrides` was supplied, so assert on
    # a section the override never mentioned.
    assert "defaultRequestPolicy" in effective["http"], (
        "EffectiveDeliveryPolicy must be the override merged over the defaults, so "
        f"http.defaultRequestPolicy must survive; got {sorted(effective['http'])}"
    )

    # Break exactly one thing: numRetries above the documented maximum.
    bad = json.loads(json.dumps(policy))
    bad["http"]["defaultHealthyRetryPolicy"]["numRetries"] = 200
    code, message = _err(lambda: sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="DeliveryPolicy", AttributeValue=json.dumps(bad)
    ))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for numRetries=200 (above the documented max), got {code}"
    )
    assert message == "Invalid parameter: DeliveryPolicy: http.defaultHealthyRetryPolicy.numRetries must be less than or equal to 100", (
        f"unexpected refusal message for numRetries=200: {message!r}"
    )

    # A second, structurally different rejection: an unknown backoffFunction.
    bad2 = json.loads(json.dumps(policy))
    bad2["http"]["defaultHealthyRetryPolicy"]["backoffFunction"] = "quadratic"
    code2, message2 = _err(lambda: sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="DeliveryPolicy", AttributeValue=json.dumps(bad2)
    ))
    assert code2 == "InvalidParameter", (
        f"expected InvalidParameter for an unknown backoffFunction 'quadratic', got {code2}"
    )
    # message not asserted: AWS's text for this refusal embeds server-side parser class
    # names and a byte offset into the submitted document, so it has no portable form.

    # Effect absent: both rejected writes left the accepted policy and its computed view
    # exactly as they were.
    after = _topic_attrs(sns, topic_arn)
    assert json.loads(after["DeliveryPolicy"])["http"]["defaultHealthyRetryPolicy"]["numRetries"] == 7, (
        f"a rejected DeliveryPolicy must not be persisted, got {after.get('DeliveryPolicy')!r}"
    )
    assert json.loads(after["EffectiveDeliveryPolicy"])["http"]["defaultHealthyRetryPolicy"]["numRetries"] == 7, (
        "a rejected DeliveryPolicy must not perturb the computed EffectiveDeliveryPolicy, "
        f"got {after.get('EffectiveDeliveryPolicy')!r}"
    )

    # Control: a different legal value is still accepted on the same topic, and the
    # computed view follows again.
    policy["http"]["defaultHealthyRetryPolicy"]["numRetries"] = 3
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="DeliveryPolicy", AttributeValue=json.dumps(policy)
    )
    final = _poll(
        lambda: json.loads(_topic_attrs(sns, topic_arn)["EffectiveDeliveryPolicy"]),
        lambda p: p["http"]["defaultHealthyRetryPolicy"]["numRetries"] == 3,
        timeout_s=30.0,
        interval_s=2.0,
        what="EffectiveDeliveryPolicy follows the control update to numRetries=3",
    )
    assert final["http"]["defaultHealthyRetryPolicy"]["numRetries"] == 3, (
        f"expected the control DeliveryPolicy update to take effect, got {final}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
