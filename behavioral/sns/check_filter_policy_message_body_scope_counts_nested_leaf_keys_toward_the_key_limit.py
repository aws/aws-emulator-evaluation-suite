"""filter-policy-message-body-scope-counts-nested-leaf-keys-toward-the-key-limit."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-policy-message-body-scope-counts-nested-leaf-keys-toward-the-key-limit"
GROUP = "filter-policy-limits"
SERVICES = ["sns"]


def _error(fn) -> tuple[str, str]:
    """(Code, Message) of the error ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


_FIVE = {"order": {"customer": {"tier": ["gold"], "region": ["eu"]},
                   "total": [{"numeric": [">", 0]}]},
         "source": ["web"], "kind": ["created"]}
_SIX = {"order": {"customer": {"tier": ["gold"], "region": ["eu"], "vip": ["yes"]},
                  "total": [{"numeric": [">", 0]}]},
        "source": ["web"], "kind": ["created"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Under FilterPolicyScope=MessageBody the five-key limit counts nested leaf keys: five leaves
    under three top-level keys are accepted, a sixth leaf is refused and the stored policy kept."""
    sns = ctx.client("sns")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-fpleaf-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    region, account = topic.split(":")[3], topic.split(":")[4]
    endpoint = f"arn:aws:sqs:{region}:{account}:sim2real-behav-sns-fpleaf-{uuid.uuid4().hex[:8]}"
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=endpoint, ReturnSubscriptionArn=True,
                        Attributes={"FilterPolicyScope": "MessageBody",
                                    "FilterPolicy": json.dumps(_FIVE)})["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]
    assert (attrs.get("FilterPolicyScope"), json.loads(attrs.get("FilterPolicy", "null"))) == ("MessageBody", _FIVE), (
        f"a five-leaf MessageBody policy must be accepted and stored; scope {attrs.get('FilterPolicyScope')!r}")

    code, message = _error(lambda: sns.set_subscription_attributes(
        SubscriptionArn=sub, AttributeName="FilterPolicy", AttributeValue=json.dumps(_SIX)))
    assert (code, message) == ("InvalidParameter",
                               "Invalid parameter: FilterPolicy: Filter policy can not have more than 5 keys"), (
        f"a six-leaf MessageBody policy gave {code!r}: {message!r}")
    stored = json.loads(sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]["FilterPolicy"])
    assert stored == _FIVE, "the refused six-leaf policy replaced the stored five-leaf policy"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
