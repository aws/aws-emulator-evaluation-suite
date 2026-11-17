"""bulk-tag-untag-reaches-bucket-and-table-native-tags."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bulk-tag-untag-reaches-bucket-and-table-native-tags"
GROUP = "tagging-discovery"
SERVICES = ["dynamodb", "resourcegroupstaggingapi", "s3"]


def _delete_bucket(s3, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


def _delete_table_once_tags_settle(ddb, table_name: str, timeout_s=120.0, interval_s=3.0) -> None:
    """Delete the table, retrying while DynamoDB still reports its own tag write in flight."""
    expected_message = (
        f"Attempt to change a resource which is still in use: Table tags are being updated: {table_name}"
    )
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceInUseException" and err["Message"] == expected_message:
                if time.monotonic() > deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _retry_while_table_tags_updating(call, table_arn: str, table_name: str, timeout_s=120.0, interval_s=3.0):
    """Retry a tagging-API batch call while it reports the table's own serialized-tag-write limit.

    DynamoDB accepts only one in-flight tag write per table and reports the overlap on the batch's
    per-resource FailedResourcesMap rather than raising, so the retry reads that map, not an
    exception.
    """
    expected_message = f"Subscriber limit exceeded: Table tags are being updated: {table_name}"
    deadline = time.monotonic() + timeout_s
    while True:
        result = call()
        detail = result["FailedResourcesMap"].get(table_arn)
        if not (detail and detail["ErrorCode"] == "LimitExceededException"
                and detail["ErrorMessage"] == expected_message):
            return result
        if time.monotonic() > deadline:
            return result
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A single TagResources/UntagResources call over an S3 bucket ARN and a DynamoDB table ARN
    adds a key, removes a seeded key and keeps a third, visible through GetBucketTagging,
    ListTagsOfResource and GetResources, with an empty FailedResourcesMap on both calls."""
    s3 = ctx.client("s3")
    ddb = ctx.client("dynamodb")
    rgt = ctx.client("resourcegroupstaggingapi")

    keep_key = ctx.unique_name("sim2real-behav-keep-")
    drop_key = ctx.unique_name("sim2real-behav-drop-")
    added_key = ctx.unique_name("sim2real-behav-added-")
    keep_value = ctx.unique_name("sim2real-behav-kv-")
    drop_value = ctx.unique_name("sim2real-behav-dv-")
    added_value = ctx.unique_name("sim2real-behav-av-")

    bucket = ctx.unique_name("sim2real-behav-bkt-")
    create_params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": keep_key, "Value": keep_value}, {"Key": drop_key, "Value": drop_value}]},
    )
    bucket_arn = f"arn:aws:s3:::{bucket}"

    table_name = ctx.unique_name("sim2real-behav-tbl-")
    created = ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    table_arn = created["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: _delete_table_once_tags_settle(ddb, table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.tag_resource(ResourceArn=table_arn, Tags=[{"Key": keep_key, "Value": keep_value}, {"Key": drop_key, "Value": drop_value}])

    # DynamoDB applies a TagResource write asynchronously and refuses an overlapping one with
    # LimitExceededException, so the seed write must be visible before the bulk call below.
    seeded = {keep_key: keep_value, drop_key: drop_value}
    _poll_until(
        lambda: {t["Key"]: t["Value"] for t in ddb.list_tags_of_resource(ResourceArn=table_arn)["Tags"]},
        lambda m: m == seeded,
        timeout_s=120.0,
    )

    tagged = _retry_while_table_tags_updating(
        lambda: rgt.tag_resources(ResourceARNList=[bucket_arn, table_arn], Tags={added_key: added_value}),
        table_arn, table_name,
    )
    assert tagged["FailedResourcesMap"] == {}, (
        f"TagResources over the bucket and the table reported per-resource failures: "
        f"{tagged['FailedResourcesMap']!r}"
    )

    untagged = _retry_while_table_tags_updating(
        lambda: rgt.untag_resources(ResourceARNList=[bucket_arn, table_arn], TagKeys=[drop_key]),
        table_arn, table_name,
    )
    assert untagged["FailedResourcesMap"] == {}, (
        f"UntagResources over the bucket and the table reported per-resource failures: "
        f"{untagged['FailedResourcesMap']!r}"
    )

    want = {keep_key: keep_value, added_key: added_value}

    bucket_tags = _poll_until(
        lambda: {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]},
        lambda m: m == want,
        timeout_s=120.0,
    )
    assert bucket_tags == want, (
        f"the bucket's own GetBucketTagging reports {bucket_tags!r} after TagResources added "
        f"{added_key}={added_value!r} and UntagResources removed {drop_key!r}; expected {want!r}"
    )

    table_tags = _poll_until(
        lambda: {t["Key"]: t["Value"] for t in ddb.list_tags_of_resource(ResourceArn=table_arn)["Tags"]},
        lambda m: m == want,
        timeout_s=120.0,
    )
    assert table_tags == want, (
        f"the table's own ListTagsOfResource reports {table_tags!r} after TagResources added "
        f"{added_key}={added_value!r} and UntagResources removed {drop_key!r}; expected {want!r}"
    )

    mappings = _poll_until(
        lambda: rgt.get_resources(ResourceARNList=[bucket_arn, table_arn])["ResourceTagMappingList"],
        lambda ms: len(ms) == 2 and all({t["Key"]: t["Value"] for t in m["Tags"]} == want for m in ms),
        timeout_s=180.0,
    )
    by_arn = {m["ResourceARN"]: {t["Key"]: t["Value"] for t in m["Tags"]} for m in mappings}
    assert set(by_arn) == {bucket_arn, table_arn}, (
        f"GetResources over the two ARNs returned {sorted(by_arn)!r}, expected exactly "
        f"[{bucket_arn!r}, {table_arn!r}]"
    )
    assert by_arn[bucket_arn] == want, (
        f"GetResources reports the bucket's tag set as {by_arn[bucket_arn]!r}, expected {want!r}"
    )
    assert by_arn[table_arn] == want, (
        f"GetResources reports the table's tag set as {by_arn[table_arn]!r}, expected {want!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
