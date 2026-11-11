"""topic-mutable-attributes-round-trip-and-clear."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "topic-mutable-attributes-round-trip-and-clear"
GROUP = 'topic-attributes'
SERVICES = ['sns']


def _attrs(sns, arn):
    return sns.get_topic_attributes(TopicArn=arn)["Attributes"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisplayName, the KMS key id, TracingConfig and SignatureVersion each round-trip through
    SetTopicAttributes, each write changes only its own attribute, and setting DisplayName and the
    KMS key id to the empty string clears them back to their defaults."""
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-mutattr-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    # SNS stores the KMS key id without resolving it and nothing is published, so no key exists.
    alias = f"alias/{ctx.unique_name('sim2real-behav-sns-key-')}"

    base = _attrs(sns, arn)
    assert base.get("DisplayName") == "", f"a new topic's DisplayName defaults to '', got {base.get('DisplayName')!r}"
    assert "KmsMasterKeyId" not in base, "a new topic carries no KmsMasterKeyId"
    unset = sorted(k for k in ("TracingConfig", "SignatureVersion") if k in base)
    assert not unset, f"a new topic reports no TracingConfig or SignatureVersion until set, got {unset!r}"

    writes = [("DisplayName", "Alerts"), ("KmsMasterKeyId", alias),
              ("TracingConfig", "Active"), ("SignatureVersion", "2")]
    expected = {}
    for name, value in writes:
        sns.set_topic_attributes(TopicArn=arn, AttributeName=name, AttributeValue=value)
        expected[name] = value
        got = _attrs(sns, arn)
        seen = {k: got.get(k) for k in expected}
        assert seen == expected, f"after setting {name}, the written attributes read back as {seen!r}"

    sns.set_topic_attributes(TopicArn=arn, AttributeName="DisplayName", AttributeValue="")
    sns.set_topic_attributes(TopicArn=arn, AttributeName="KmsMasterKeyId", AttributeValue="")
    final = _attrs(sns, arn)
    assert final.get("DisplayName") == "", f"an empty DisplayName must clear it, got {final.get('DisplayName')!r}"
    assert "KmsMasterKeyId" not in final, (
        f"an empty KmsMasterKeyId must remove the attribute, got {final.get('KmsMasterKeyId')!r}"
    )
    kept = {k: final.get(k) for k in ("TracingConfig", "SignatureVersion")}
    assert kept == {"TracingConfig": "Active", "SignatureVersion": "2"}, (
        f"clearing two attributes must leave the other writes in place, got {kept!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
