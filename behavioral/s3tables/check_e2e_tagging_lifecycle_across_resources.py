"""e2e-tagging-lifecycle-across-resources."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "e2e-tagging-lifecycle-across-resources"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags on a table bucket and on a table in it are separate: ListTagsForResource returns each one's
    own tag, and after UntagResource on the bucket only, the table still carries its tag."""
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-s3t-tag-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    namespace_name = _sanitize(ctx.unique_name("sim2real_ns_"))
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace_name])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace_name))

    table_name = _sanitize(ctx.unique_name("sim2real_tbl_"))
    table_arn = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name, format="ICEBERG"
    )["tableARN"]
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name)
    )

    s3tables.tag_resource(resourceArn=bucket_arn, tags={"sim2real-scope": "bucket"})
    s3tables.tag_resource(resourceArn=table_arn, tags={"sim2real-scope": "table"})

    bucket_tags = s3tables.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    table_tags = s3tables.list_tags_for_resource(resourceArn=table_arn)["tags"]
    assert bucket_tags == {"sim2real-scope": "bucket"}, bucket_tags
    assert table_tags == {"sim2real-scope": "table"}, table_tags

    s3tables.untag_resource(resourceArn=bucket_arn, tagKeys=["sim2real-scope"])

    bucket_tags_after = s3tables.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    table_tags_after = s3tables.list_tags_for_resource(resourceArn=table_arn)["tags"]
    assert "sim2real-scope" not in bucket_tags_after, bucket_tags_after
    assert table_tags_after == {"sim2real-scope": "table"}, table_tags_after


def _sanitize(name: str) -> str:
    return re.sub(r"[^0-9a-z_]", "_", name.lower())


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
