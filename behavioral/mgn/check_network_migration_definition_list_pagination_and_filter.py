"""network-migration-definition-list-pagination-and-filter."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-migration-definition-list-pagination-and-filter"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNetworkMigrationDefinitions with a networkMigrationDefinitionIDs filter returns
    exactly the requested definitions (not the whole account's set), and maxResults paginates
    via nextToken rather than truncating silently."""
    mgn = ctx.client("mgn")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    src_bucket, src_key = _make_source_object(ctx)

    def _create(tag: str) -> str:
        name = ctx.unique_name(f"sim2real-mgn-nmd-{tag}-")
        created = mgn.create_network_migration_definition(
            name=name,
            sourceConfigurations=[
                {
                    "sourceEnvironment": "LOGICAL_MODEL",
                    "sourceS3Configuration": {
                        "s3Bucket": src_bucket,
                        "s3BucketOwner": account_id,
                        "s3Key": src_key,
                    },
                }
            ],
            targetS3Configuration={"s3Bucket": src_bucket, "s3BucketOwner": account_id},
            targetNetwork={
                "topology": "ISOLATED_VPC",
                "inboundCidr": "10.0.0.0/24",
                "outboundCidr": "10.0.1.0/24",
                "inspectionCidr": "10.0.2.0/24",
            },
            tags={"sim2real": CHECK},
        )
        nmd_id = created["networkMigrationDefinitionID"]
        ctx.on_cleanup(lambda: mgn.delete_network_migration_definition(networkMigrationDefinitionID=nmd_id))
        return nmd_id

    ids = [_create(str(i)) for i in range(3)]

    # Filtering by a subset of IDs must return exactly that subset.
    subset = ids[:2]
    filtered = mgn.list_network_migration_definitions(
        filters={"networkMigrationDefinitionIDs": subset}
    )["items"]
    filtered_ids = {item["networkMigrationDefinitionID"] for item in filtered}
    assert filtered_ids == set(subset), (
        f"filter by networkMigrationDefinitionIDs must return exactly the requested set, "
        f"expected {set(subset)}, got {filtered_ids}"
    )

    # maxResults=1 must paginate via nextToken rather than silently dropping the rest.
    page1 = mgn.list_network_migration_definitions(
        filters={"networkMigrationDefinitionIDs": ids}, maxResults=1
    )
    assert len(page1["items"]) == 1, (
        f"maxResults=1 must return exactly 1 item per page, got {len(page1['items'])}"
    )
    seen = {page1["items"][0]["networkMigrationDefinitionID"]}
    next_token = page1.get("nextToken")
    guard = 0
    while next_token and guard < 10:
        page = mgn.list_network_migration_definitions(
            filters={"networkMigrationDefinitionIDs": ids}, maxResults=1, nextToken=next_token
        )
        for item in page["items"]:
            seen.add(item["networkMigrationDefinitionID"])
        next_token = page.get("nextToken")
        guard += 1
    assert seen == set(ids), f"pagination must eventually surface all {set(ids)}, saw {seen}"


def _make_source_object(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mgn-nmd-src-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    key = "sim2real/source-model.json"
    s3.put_object(Bucket=bucket, Key=key, Body=b"{}")

    def _cleanup():
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket, key


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
