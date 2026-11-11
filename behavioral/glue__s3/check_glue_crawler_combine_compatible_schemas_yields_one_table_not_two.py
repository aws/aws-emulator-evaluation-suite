"""glue-crawler-combine-compatible-schemas-yields-one-table-not-two."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "glue-crawler-combine-compatible-schemas-yields-one-table-not-two"
GROUP = "crawlers"
SERVICES = ["glue", "s3"]

# part1's `id` is integers (Glue infers BIGINT), part2's is decimal (DOUBLE). That widening is
# data-compatible (folds under CombineCompatibleSchemas) but not schema-similar (the default policy
# splits it); an added column alone does not split, and a STRING/BIGINT clash folds under neither.
_PART1_CSV = b"id,name\n1,alice\n2,bob\n3,carol\n"
_PART2_CSV = b"id,name,extra\n4.5,dave,d\n5.5,erin,e\n6.5,frank,f\n"
_GROUPING = json.dumps({"Version": 1.0,
                        "Grouping": {"TableGroupingPolicy": "CombineCompatibleSchemas"}})


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """CombineCompatibleSchemas folds two compatible child prefixes into one table; the default policy does not."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-gluegrp-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="data/part1/rows.csv", Body=_PART1_CSV)
    s3.put_object(Bucket=bucket, Key="data/part2/rows.csv", Body=_PART2_CSV)

    role_arn = _create_glue_role(ctx, iam, bucket)
    include_path = f"s3://{bucket}/data/"

    # Two databases so neither crawler can observe or mutate the other's output. Everything
    # else about the two crawlers is identical, which is what makes the count difference
    # attributable to the one setting.
    default_db = ctx.unique_name("sim2real_behav_grpdef_").replace("-", "_")
    grouped_db = ctx.unique_name("sim2real_behav_grpcmb_").replace("-", "_")
    for database in (default_db, grouped_db):
        glue.create_database(DatabaseInput={"Name": database})
        ctx.on_cleanup(lambda d=database: _retry_delete(
            lambda: glue.delete_database(Name=d), f"glue database {d}"))

    default_crawler = _create_crawler(
        ctx, glue,
        Name=ctx.unique_name("sim2real-behav-grpdef-"),
        Role=role_arn,
        DatabaseName=default_db,
        Targets={"S3Targets": [{"Path": include_path}]},
        SchemaChangePolicy={"UpdateBehavior": "UPDATE_IN_DATABASE", "DeleteBehavior": "LOG"},
        RecrawlPolicy={"RecrawlBehavior": "CRAWL_EVERYTHING"},
        Tags={"sim2real": CHECK},
    )
    grouped_crawler = _create_crawler(
        ctx, glue,
        Name=ctx.unique_name("sim2real-behav-grpcmb-"),
        Role=role_arn,
        DatabaseName=grouped_db,
        Targets={"S3Targets": [{"Path": include_path}]},
        SchemaChangePolicy={"UpdateBehavior": "UPDATE_IN_DATABASE", "DeleteBehavior": "LOG"},
        RecrawlPolicy={"RecrawlBehavior": "CRAWL_EVERYTHING"},
        Configuration=_GROUPING,
        Tags={"sim2real": CHECK},
    )

    # The grouping policy is really stored, and the control crawler really does NOT carry it.
    grouped_config = json.loads(glue.get_crawler(Name=grouped_crawler)["Crawler"]
                                ["Configuration"])
    assert grouped_config["Grouping"]["TableGroupingPolicy"] == "CombineCompatibleSchemas", (
        f"GetCrawler({grouped_crawler}) reports Configuration={grouped_config!r}; the grouping "
        f"policy must be stored or every assertion below is vacuous"
    )
    default_described = glue.get_crawler(Name=default_crawler)["Crawler"]
    assert "TableGroupingPolicy" not in (default_described.get("Configuration") or ""), (
        f"the control crawler {default_crawler} carries Configuration="
        f"{default_described.get('Configuration')!r}; it must not set a grouping policy, or "
        f"the two arms are not a twin pair"
    )

    # Both crawls run against the same bytes at the same time, so a divergence in table count
    # cannot be blamed on the data changing.
    glue.start_crawler(Name=default_crawler)
    glue.start_crawler(Name=grouped_crawler)
    last = _crawlers_to_ready(glue, [default_crawler, grouped_crawler])
    for crawler, record in last.items():
        assert record.get("Status") == "SUCCEEDED", (
            f"crawler {crawler} finished with LastCrawl={record!r}"
        )

    default_tables = _get_tables(ctx, glue, default_db)
    grouped_tables = _get_tables(ctx, glue, grouped_db)

    # The derivation rule: the SAME include path yields strictly fewer tables under the grouping
    # policy. An emulator that stores Configuration and ignores it produces the same count in
    # both arms and fails here whichever count it happens to produce.
    assert len(grouped_tables) < len(default_tables), (
        f"CombineCompatibleSchemas produced {len(grouped_tables)} tables "
        f"({sorted(grouped_tables)}) and the default policy produced {len(default_tables)} "
        f"({sorted(default_tables)}) over the identical include path {include_path!r}. The "
        f"grouping policy must fold compatible child folders, so the grouped count must be "
        f"strictly smaller; equal counts mean the Configuration was stored and ignored"
    )
    assert len(default_tables) == 2, (
        f"the default crawler produced {len(default_tables)} tables "
        f"({sorted(default_tables)}) over two child prefixes with different-but-compatible "
        f"schemas, expected 2 — one per folder"
    )
    assert len(grouped_tables) == 1, (
        f"CombineCompatibleSchemas produced {len(grouped_tables)} tables "
        f"({sorted(grouped_tables)}), expected exactly 1 combined table"
    )

    # An independent read at the catalogue (the crawl's destination), through GetTable rather
    # than through the crawler's own report: the combined table spans the whole include path and
    # its columns are the union of the two child schemas.
    combined = glue.get_table(DatabaseName=grouped_db, Name=grouped_tables[0])["Table"]
    assert combined["StorageDescriptor"]["Location"].rstrip("/") == include_path.rstrip("/"), (
        f"the combined table points at {combined['StorageDescriptor']['Location']!r}, expected "
        f"the include path root {include_path!r}: a table folded from both children must be "
        f"rooted above them"
    )
    columns = {c["Name"] for c in combined["StorageDescriptor"]["Columns"]}
    assert {"id", "name", "extra"} <= columns, (
        f"the combined table's columns are {sorted(columns)}; folding part1 (id, name) and "
        f"part2 (id, name, extra) must yield at least the union of the two child schemas"
    )
    partition_keys = [k["Name"] for k in combined["PartitionKeys"]]
    assert len(partition_keys) == 1, (
        f"the combined table declares PartitionKeys={partition_keys!r}, expected exactly one — "
        f"the folded child folders become partitions of the single table"
    )
    partitions = _partition_values(glue, grouped_db, grouped_tables[0])
    assert partitions == [["part1"], ["part2"]], (
        f"the combined table holds partitions {partitions!r}, expected [['part1'], ['part2']]: "
        f"both child folders must be registered as partitions of the one table, not dropped"
    )

    # And the control arm really did split them, so "fewer tables" is not "fewer tables because
    # the crawler found nothing".
    default_locations = sorted(
        glue.get_table(DatabaseName=default_db, Name=n)["Table"]
        ["StorageDescriptor"]["Location"].rstrip("/")
        for n in default_tables
    )
    assert default_locations == [f"s3://{bucket}/data/part1", f"s3://{bucket}/data/part2"], (
        f"the default crawler's tables point at {default_locations!r}, expected one per child "
        f"prefix; without that the count of 2 does not mean it split by folder"
    )


# ===== helpers =====

def _partition_values(glue, database: str, table: str) -> list:
    values = []
    for page in glue.get_paginator("get_partitions").paginate(DatabaseName=database,
                                                              TableName=table):
        values.extend(p["Values"] for p in page["Partitions"])
    return sorted(values)


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, bucket: str) -> str:
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    role = ctx.unique_name("sim2real-behav-gluerole-")
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    # Registered first so it runs last: DeleteRole refuses while any policy is still attached.
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role),
                                         f"iam role {role}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}"))
    iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                       "Resource": f"arn:aws:s3:::{bucket}/*"},
                      {"Effect": "Allow", "Action": ["s3:ListBucket"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    return arn


def _create_crawler(ctx, glue, *, timeout_s: float = 180.0, **kwargs) -> str:
    """CreateCrawler validates synchronously that Glue can assume the role, so it raises
    InvalidInputException while IAM propagation is still in flight; retry until it clears.
    IAM exposes no condition that reports a role has become assumable by a service."""
    from botocore.exceptions import ClientError

    name = kwargs["Name"]
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_crawler(**kwargs)
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInputException" \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_crawler(Name=name),
                                         f"glue crawler {name}"))
    return name


def _crawlers_to_ready(glue, crawlers: list, *, timeout_s: float = 900.0) -> dict:
    """Wait for every crawler to return to READY, returning each one's LastCrawl. Raises on
    timeout: a crawler stuck in RUNNING must fail the check, never be graded on a stale
    LastCrawl."""
    deadline = time.monotonic() + timeout_s
    settled: dict = {}
    while time.monotonic() < deadline:
        states = {}
        for crawler in crawlers:
            described = glue.get_crawler(Name=crawler)["Crawler"]
            states[crawler] = described.get("State")
            if described.get("State") == "READY":
                settled[crawler] = described.get("LastCrawl", {})
        if len(settled) == len(crawlers):
            return settled
        time.sleep(2)
    raise AssertionError(
        f"crawlers {[c for c in crawlers if c not in settled]!r} did not return to READY "
        f"within {timeout_s}s")


def _get_tables(ctx, glue, database: str) -> list:
    names = []
    for page in glue.get_paginator("get_tables").paginate(DatabaseName=database):
        for table in page["TableList"]:
            names.append(table["Name"])
            ctx.on_cleanup(lambda n=table["Name"]: _retry_delete(
                lambda: glue.delete_table(DatabaseName=database, Name=n),
                f"glue table {database}.{n}"))
    return sorted(set(names))


def _retry_delete(fn, label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions: a
    throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "CrawlerRunningException", "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    _retry_delete(lambda: s3.delete_bucket(Bucket=bucket), f"s3 bucket {bucket}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
