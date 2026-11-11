"""tag-resource-list-untag-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-list-untag-roundtrip"
GROUP = "data-plane"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip against a real
    vocabulary ARN: tags actually persist and actually get removed."""
    tx = ctx.client("transcribe")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-vocab-tags-")
    tx.create_vocabulary(VocabularyName=name, LanguageCode="en-US", Phrases=["Alpha"])
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, name))

    account_id = sts.get_caller_identity()["Account"]
    arn = f"arn:aws:transcribe:{ctx.region}:{account_id}:vocabulary/{name}"

    tx.tag_resource(ResourceArn=arn, Tags=[{"Key": "sim2real-env", "Value": "behavioral"}])
    tags = tx.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert {"Key": "sim2real-env", "Value": "behavioral"} in tags, (
        f"expected tag sim2real-env=behavioral in {tags}"
    )

    tx.untag_resource(ResourceArn=arn, TagKeys=["sim2real-env"])
    tags_after = tx.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert all(t["Key"] != "sim2real-env" for t in tags_after), f"tag survived untag: {tags_after}"


def _delete_vocabulary_ignore_missing(ctx, name: str) -> None:
    tx = ctx.client("transcribe")
    try:
        tx.delete_vocabulary(VocabularyName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "BadRequestException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
