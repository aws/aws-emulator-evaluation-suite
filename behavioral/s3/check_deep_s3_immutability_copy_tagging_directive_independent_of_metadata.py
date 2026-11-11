"""deep-s3-immutability-copy-tagging-directive-independent-of-metadata."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-immutability-copy-tagging-directive-independent-of-metadata"
GROUP = 'copy-directives'
SERVICES = ['s3']

_BODY = b"tagged-source-bytes"
_SRC_META = {"owner": "team-a"}
_SRC_TAGS = [{"Key": "class", "Value": "gold"}, {"Key": "tier", "Value": "hot"}]


def _delete_bucket(client, bucket):
    """Delete every version and marker, then the bucket."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-imm-")
    params = {"Bucket": name}
    # us-east-1 is the one region that rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _tags_of(s3, bucket, key):
    return sorted(
        (t["Key"], t["Value"]) for t in s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject applies TaggingDirective and MetadataDirective independently across all four
    combinations, an omitted TaggingDirective means COPY, TaggingDirective=REPLACE without Tagging
    yields an empty tag set, and the source's tags and metadata stay unchanged."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    src_tags = sorted((t["Key"], t["Value"]) for t in _SRC_TAGS)
    s3.put_object(
        Bucket=bucket, Key="src.bin", Body=_BODY, Metadata=_SRC_META,
        Tagging="&".join(f"{t['Key']}={t['Value']}" for t in _SRC_TAGS),
    )
    assert _tags_of(s3, bucket, "src.bin") == src_tags, "the source's inline tags did not land"
    source = {"Bucket": bucket, "Key": "src.bin"}

    # (metadata COPY, tagging REPLACE)
    s3.copy_object(Bucket=bucket, Key="mc-tr.bin", CopySource=source, MetadataDirective="COPY",
                   TaggingDirective="REPLACE", Tagging="class=bronze")
    # (metadata REPLACE, tagging COPY)
    s3.copy_object(Bucket=bucket, Key="mr-tc.bin", CopySource=source, MetadataDirective="REPLACE",
                   Metadata={"owner": "team-b"}, TaggingDirective="COPY")
    # (metadata REPLACE, tagging REPLACE)
    s3.copy_object(Bucket=bucket, Key="mr-tr.bin", CopySource=source, MetadataDirective="REPLACE",
                   Metadata={"owner": "team-c"}, TaggingDirective="REPLACE", Tagging="tier=cold")
    # (both omitted: both default to COPY)
    s3.copy_object(Bucket=bucket, Key="default.bin", CopySource=source)
    # (tagging REPLACE with no Tagging at all: the tag set is emptied)
    s3.copy_object(Bucket=bucket, Key="tr-empty.bin", CopySource=source, TaggingDirective="REPLACE")

    want = {
        "mc-tr.bin": (_SRC_META, [("class", "bronze")]),
        "mr-tc.bin": ({"owner": "team-b"}, src_tags),
        "mr-tr.bin": ({"owner": "team-c"}, [("tier", "cold")]),
        "default.bin": (_SRC_META, src_tags),
        "tr-empty.bin": (_SRC_META, []),
    }
    observed = {}
    for key in want:
        head = s3.head_object(Bucket=bucket, Key=key)
        observed[key] = (head["Metadata"], _tags_of(s3, bucket, key))
        assert head.get("TagCount", 0) == len(want[key][1]), (
            f"{key}: HeadObject TagCount {head.get('TagCount')!r} disagrees with the "
            f"{len(want[key][1])} tags expected"
        )
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert body == _BODY, f"{key}: the copy holds {body!r}, want {_BODY!r}"
    assert observed == want, (
        f"(metadata, tags) per destination were {observed!r}; want {want!r} — the two directives "
        "must act independently"
    )

    # The source is untouched by any of the five copies.
    assert _tags_of(s3, bucket, "src.bin") == src_tags, "copying changed the source's tags"
    assert s3.head_object(Bucket=bucket, Key="src.bin")["Metadata"] == _SRC_META, (
        "copying changed the source's metadata"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
