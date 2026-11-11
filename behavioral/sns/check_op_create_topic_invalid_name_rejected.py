"""op-create-topic-invalid-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-create-topic-invalid-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _topic_names(sns):
    names = set()
    paginator = sns.get_paginator("list_topics")
    for page in paginator.paginate():
        for t in page.get("Topics", []):
            names.add(t["TopicArn"].rsplit(":", 1)[-1])
    return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTopic must reject names containing characters outside [A-Za-z0-9_-] and names over 256 chars, and must not create anything as a side effect."""
    sns = ctx.client("sns")

    # Positive control: the same operation, a valid name, succeeds -- so the two
    # rejections below prove something about invalid names, not merely that every
    # CreateTopic call fails in this account.
    good_name = ctx.unique_name("sim2real-behav-sns-validname-")
    good_arn = sns.create_topic(
        Name=good_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=good_arn))
    attrs = sns.get_topic_attributes(TopicArn=good_arn)
    assert attrs["Attributes"]["TopicArn"] == good_arn, (
        f"positive control: GetTopicAttributes did not resolve the created topic {good_arn!r}"
    )

    bad_char_name = ctx.unique_name("bad name!") + "$"
    code, message = _error(lambda: sns.create_topic(Name=bad_char_name))
    assert code == "InvalidParameter", f"expected InvalidParameter for an illegal topic name, got {code}"
    expected = 'Invalid parameter: Topic Name'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # 257-character name exceeds the documented 256-char limit.
    long_name = "a" * 257
    code, message = _error(lambda: sns.create_topic(Name=long_name))
    assert code == "InvalidParameter", f"expected InvalidParameter for an over-long topic name, got {code}"
    expected = 'Invalid parameter: Topic Name'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: an independent read at the destination shows neither rejected
    # name was created as a side effect of the refused calls.
    names = _topic_names(sns)
    assert bad_char_name not in names, f"rejected topic name {bad_char_name!r} appears in ListTopics"
    assert long_name not in names, "rejected over-long topic name appears in ListTopics"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
