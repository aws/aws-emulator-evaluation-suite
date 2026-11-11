"""set-topic-attribute-invalid-policy-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "set-topic-attribute-invalid-policy-rejected"
GROUP = "server-side"
SERVICES = ["sns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetTopicAttributes rejects a malformed Policy document and leaves the existing policy
    untouched; a well-formed Policy update on the same topic then succeeds and round-trips.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-badpolicy-topic-"),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    original_policy = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"]

    code, message = _error(
        lambda: sns.set_topic_attributes(
            TopicArn=topic_arn, AttributeName="Policy", AttributeValue="{this is not valid json"
        )
    )
    assert code == "InvalidParameter", f"expected InvalidParameter for a malformed Policy document, got {code!r}"
    assert message == 'Invalid parameter: Policy Error: null', (
        f"expected the exact message 'Invalid parameter: Policy Error: null', got {message!r}"
    )

    unchanged_policy = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"]
    assert unchanged_policy == original_policy, "topic policy mutated despite rejected SetTopicAttributes call"

    # positive control: a well-formed Policy update on the SAME attribute still succeeds and round-trips,
    # isolating the malformed-document rejection above rather than a blanket refusal to update Policy at all
    account = ctx.client("sts").get_caller_identity()["Account"]
    good_policy = json.dumps(
        {
            "Version": "2008-10-17",
            "Id": "sim2real-badpolicy-policy",
            "Statement": [
                {
                    "Sid": "AllowSameAccountPublish",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": "SNS:Publish",
                    "Resource": topic_arn,
                }
            ],
        }
    )
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=good_policy)
    fetched_policy = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"]
    assert json.loads(fetched_policy) == json.loads(good_policy), (
        f"well-formed Policy update did not round-trip: expected {good_policy}, got {fetched_policy}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected SetTopicAttributes to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
