"""unicode-tag-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "unicode-tag-value-round-trip"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag keys/values containing multi-script unicode text are stored and returned
    character-for-character identical -- no mangling, normalization, or truncation.
    """
    s3tables = ctx.client("s3tables")
    bucket_arn = s3tables.create_table_bucket(name=ctx.unique_name("sim2real-unicode-tag-"))["arn"]
    ctx.on_cleanup(lambda: _delete_bucket(s3tables, bucket_arn))

    unicode_tags = {
        "cafe-key": "café-résumé-naïve",
        "japanese-key": "東京タワー日本語",
        "cyrillic-key": "Москва-привет",
        "mixed-key": "Björk_Ångström_Zürich",
    }
    s3tables.tag_resource(resourceArn=bucket_arn, tags=unicode_tags)

    retrieved = s3tables.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    for key, value in unicode_tags.items():
        assert retrieved.get(key) == value, f"{key!r} round-tripped as {retrieved.get(key)!r}"
    assert len(retrieved) == len(unicode_tags), f"expected {len(unicode_tags)} tags, got {len(retrieved)}: {retrieved!r}"


def _delete_bucket(s3tables, bucket_arn: str) -> None:
    """Delete the bucket; NotFoundException means it is already gone, anything else raises."""
    from botocore.exceptions import ClientError

    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
