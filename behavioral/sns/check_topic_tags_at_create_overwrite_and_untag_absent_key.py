"""topic-tags-at-create-overwrite-and-untag-absent-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "topic-tags-at-create-overwrite-and-untag-absent-key"
GROUP = 'tagging'
SERVICES = ['sns']


def _tags(sns, arn):
    listed = sns.list_tags_for_resource(ResourceArn=arn)["Tags"]
    keys = [t["Key"] for t in listed]
    assert len(keys) == len(set(keys)), f"ListTagsForResource returned a key more than once: {sorted(keys)!r}"
    return {t["Key"]: t["Value"] for t in listed}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTopic tags are stored, TagResource on an existing key replaces its value in place, an
    empty value is legal, and UntagResource naming an absent key removes only the keys that exist.
    """
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-tagset-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "env", "Value": "dev"},
              {"Key": "owner", "Value": "team-a"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    assert _tags(sns, arn) == {"sim2real": CHECK, "env": "dev", "owner": "team-a"}, (
        f"tags given at CreateTopic must be stored exactly, got {_tags(sns, arn)!r}"
    )

    sns.tag_resource(ResourceArn=arn, Tags=[{"Key": "env", "Value": "prod"},
                                            {"Key": "empty", "Value": ""}])
    after_tag = _tags(sns, arn)
    assert after_tag == {"sim2real": CHECK, "env": "prod", "owner": "team-a", "empty": ""}, (
        f"TagResource must overwrite env in place, add empty='' and keep the rest, got {after_tag!r}"
    )

    sns.untag_resource(ResourceArn=arn, TagKeys=["owner", "never-set"])
    after_untag = _tags(sns, arn)
    assert after_untag == {"sim2real": CHECK, "env": "prod", "empty": ""}, (
        f"UntagResource must drop owner, ignore the absent key and keep the rest, got {after_untag!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
