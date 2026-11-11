"""glue-crawler-deprecate-in-database-marks-the-vanished-prefix-and-spares-its-sibling."""
# With SchemaChangePolicy.DeleteBehavior = DEPRECATE_IN_DATABASE, a recrawl that can no longer see
# a table's S3 objects leaves the table in place and adds a table property marking it deprecated:
# "to add a property to the table that says 'DEPRECATED' and includes a timestamp"
# (https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-glue-crawler-schemachangepolicy.html).
# The exact property key is not documented, so the check asserts that the set difference against
# the table's own pre-recrawl parameters holds an entry whose key or value mentions "deprecat".
# The sibling table, whose prefix is untouched, gains no such marker in the same crawl, so a
# target that deprecates everything, or nothing, fails one leg or the other. Two S3Targets with
# different schemas produce exactly two tables; both crawls end READY with LastCrawl SUCCEEDED,
# and the surviving table's inferred schema is identical across the two crawls.
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "glue-crawler-deprecate-in-database-marks-the-vanished-prefix-and-spares-its-sibling"
GROUP = "crawlers"
SERVICES = ["glue", "s3"]

# Deliberately DIFFERENT schemas so the two include paths cannot be folded into one table.
_ALPHA_CSV = b"id,name\n1,alice\n2,bob\n3,carol\n"
_BETA_CSV = b"code,score,note\nx,1.5,first\ny,2.5,second\n"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DEPRECATE_IN_DATABASE marks the table whose S3 prefix vanished and leaves its sibling alone."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-gluedep-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="alpha/rows.csv", Body=_ALPHA_CSV)
    s3.put_object(Bucket=bucket, Key="beta/rows.csv", Body=_BETA_CSV)

    role_arn = _create_glue_role(ctx, iam, bucket)

    database = ctx.unique_name("sim2real_behav_gluedep_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    crawler = ctx.unique_name("sim2real-behav-gluedep-")
    _create_crawler(
        glue,
        Name=crawler,
        Role=role_arn,
        DatabaseName=database,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/alpha/"},
                               {"Path": f"s3://{bucket}/beta/"}]},
        SchemaChangePolicy={"UpdateBehavior": "UPDATE_IN_DATABASE",
                            "DeleteBehavior": "DEPRECATE_IN_DATABASE"},
        RecrawlPolicy={"RecrawlBehavior": "CRAWL_EVERYTHING"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_crawler(Name=crawler),
                                         f"glue crawler {crawler}"))

    # The configured policy is what the crawler actually holds. A target that silently dropped
    # DeleteBehavior would make every assertion below vacuous.
    described = glue.get_crawler(Name=crawler)["Crawler"]
    assert described["SchemaChangePolicy"]["DeleteBehavior"] == "DEPRECATE_IN_DATABASE", (
        f"GetCrawler reports DeleteBehavior="
        f"{described['SchemaChangePolicy'].get('DeleteBehavior')!r}, expected "
        f"'DEPRECATE_IN_DATABASE'; the whole check rests on that setting being stored"
    )

    # --- crawl 1: both prefixes present -------------------------------------------------
    first = _crawl_to_ready(glue, crawler)
    assert first.get("Status") == "SUCCEEDED", f"first crawl LastCrawl was {first!r}"

    tables = _get_tables(ctx, glue, database)
    assert len(tables) == 2, (
        f"the first crawl created {len(tables)} tables ({sorted(tables)}); two include paths "
        f"with different schemas must yield exactly two tables for the deprecation twin to "
        f"have a control"
    )
    alpha = _table_for(glue, database, tables, f"s3://{bucket}/alpha/")
    beta = _table_for(glue, database, tables, f"s3://{bucket}/beta/")

    before_alpha = glue.get_table(DatabaseName=database, Name=alpha)["Table"]
    before_beta = glue.get_table(DatabaseName=database, Name=beta)["Table"]
    alpha_params_before = dict(before_alpha.get("Parameters", {}))
    beta_params_before = dict(before_beta.get("Parameters", {}))
    alpha_columns_before = [(c["Name"], c["Type"])
                            for c in before_alpha["StorageDescriptor"]["Columns"]]

    assert not _deprecation_entries(alpha_params_before), (
        f"{alpha} already carried a deprecation marker after the FIRST crawl: "
        f"{_deprecation_entries(alpha_params_before)!r}; the marker must only appear once its "
        f"data is gone"
    )
    assert not _deprecation_entries(beta_params_before), (
        f"{beta} already carried a deprecation marker after the FIRST crawl: "
        f"{_deprecation_entries(beta_params_before)!r}"
    )

    # --- break exactly one thing: beta's objects go away, alpha's do not ----------------
    _delete_prefix(s3, bucket, "beta/")
    remaining = s3.list_objects_v2(Bucket=bucket, Prefix="beta/").get("KeyCount", 0)
    assert remaining == 0, (
        f"s3://{bucket}/beta/ still holds {remaining} objects after the delete; the crawler "
        f"must find nothing there for DeleteBehavior to engage"
    )
    still_there = s3.list_objects_v2(Bucket=bucket, Prefix="alpha/")["KeyCount"]
    assert still_there == 1, (
        f"s3://{bucket}/alpha/ holds {still_there} objects, expected the 1 this check "
        f"uploaded; only beta may be emptied"
    )

    # --- crawl 2: beta's data is gone ----------------------------------------------------
    second = _crawl_to_ready(glue, crawler)
    assert second.get("Status") == "SUCCEEDED", (
        f"the recrawl LastCrawl was {second!r}; a crawl that finds a vanished table is still a "
        f"successful crawl"
    )

    # The terminal assertions, all independent reads at the catalog (the consumer of the crawl),
    # through GetTable rather than through GetCrawler's own report of what it did.
    after_beta = glue.get_table(DatabaseName=database, Name=beta)["Table"]
    beta_added = {k: v for k, v in after_beta.get("Parameters", {}).items()
                  if beta_params_before.get(k) != v}
    beta_markers = _deprecation_entries(beta_added)
    assert beta_markers, (
        f"the recrawl added {sorted(beta_added)} to {beta}'s Parameters and none of it marks "
        f"the table deprecated. DeleteBehavior=DEPRECATE_IN_DATABASE must add a property "
        f"saying DEPRECATED with a timestamp. Before: {sorted(beta_params_before)}; after: "
        f"{sorted(after_beta.get('Parameters', {}))}"
    )

    after_alpha = glue.get_table(DatabaseName=database, Name=alpha)["Table"]
    alpha_added = {k: v for k, v in after_alpha.get("Parameters", {}).items()
                   if alpha_params_before.get(k) != v}
    assert not _deprecation_entries(alpha_added), (
        f"the recrawl also marked the SURVIVING table {alpha} deprecated "
        f"({_deprecation_entries(alpha_added)!r}); its prefix s3://{bucket}/alpha/ still holds "
        f"its data, so a target that deprecates every table is indistinguishable from one that "
        f"implements the policy correctly without this control"
    )
    alpha_columns_after = [(c["Name"], c["Type"])
                          for c in after_alpha["StorageDescriptor"]["Columns"]]
    assert alpha_columns_after == alpha_columns_before, (
        f"the recrawl changed the surviving table's schema from {alpha_columns_before!r} to "
        f"{alpha_columns_after!r}; nothing about alpha's data changed"
    )

    # And the deprecated table is still THERE — this is the half that separates
    # DEPRECATE_IN_DATABASE from DELETE_FROM_DATABASE, and the half an emulator that treats all
    # three enum values alike will fail.
    listed = _get_tables(ctx, glue, database)
    assert beta in listed, (
        f"GetTables no longer lists {beta} after the recrawl ({sorted(listed)}); "
        f"DEPRECATE_IN_DATABASE must mark the table, not remove it — removing it is "
        f"DELETE_FROM_DATABASE"
    )


# ===== helpers =====

def _deprecation_entries(params: dict) -> dict:
    """Entries whose key or value mentions deprecation. The exact key is a hypothesis, so
    the rule is stated over the target's own parameter set rather than pinned to a literal."""
    return {k: v for k, v in params.items()
            if "deprecat" in k.lower() or "deprecat" in str(v).lower()}


def _table_for(glue, database: str, names: list, location: str) -> str:
    """The single table whose StorageDescriptor.Location is `location`. Hard-fails rather than
    returning a sentinel, so a crawl that produced the wrong layout is loud."""
    matches = [
        n for n in names
        if glue.get_table(DatabaseName=database, Name=n)["Table"]
        ["StorageDescriptor"]["Location"].rstrip("/") == location.rstrip("/")
    ]
    assert len(matches) == 1, (
        f"expected exactly 1 table at {location!r} in {database}, found {matches!r} among "
        f"{names!r}"
    )
    return matches[0]


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _delete_prefix(s3, bucket: str, prefix: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})


def _create_glue_role(ctx, iam, bucket: str) -> str:
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    role = ctx.unique_name("sim2real-behav-gluerole-")
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _delete_glue_role(iam, role, managed))
    iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                       "Resource": f"arn:aws:s3:::{bucket}/*"},
                      {"Effect": "Allow", "Action": ["s3:ListBucket"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    ctx.on_cleanup(lambda: _delete_glue_role(iam, role, managed))
    return arn


def _delete_glue_role(iam, role: str, managed: str) -> None:
    """Teardown: remove the role's policies, then the role; DeleteRole refuses while any remain."""
    _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}",
    )
    _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}",
    )
    _retry_delete(lambda: iam.delete_role(RoleName=role), f"iam role {role}")


def _create_crawler(glue, *, timeout_s: float = 180.0, **kwargs) -> None:
    """CreateCrawler validates synchronously that Glue can assume the role, so it raises
    InvalidInputException while IAM propagation is still in flight; retry until it clears.
    IAM exposes no condition that reports a role has become assumable by a service."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInputException" \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _crawl_to_ready(glue, crawler: str, *, timeout_s: float = 600.0) -> dict:
    """Start a crawl and wait for the crawler to return to READY. Raises on timeout: a crawler
    stuck in RUNNING must fail the check, never be graded on a stale LastCrawl."""
    glue.start_crawler(Name=crawler)
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        described = glue.get_crawler(Name=crawler)["Crawler"]
        state = described.get("State")
        if state == "READY":
            return described.get("LastCrawl", {})
        time.sleep(5)
    raise AssertionError(
        f"crawler {crawler!r} did not return to READY within {timeout_s}s "
        f"(last state {state!r})")


def _get_tables(ctx, glue, database: str) -> list:
    names = []
    for page in glue.get_paginator("get_tables").paginate(DatabaseName=database):
        for table in page["TableList"]:
            names.append(table["Name"])
            ctx.on_cleanup(lambda n=table["Name"]: _retry_delete(
                lambda: glue.delete_table(DatabaseName=database, Name=n),
                f"glue table {database}.{n}"))
    return sorted(set(names))


def _retry_delete(fn, label: str, *, timeout_s: float = 60.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions: a
    throttled or dependency-blocked delete would leak silently while the check passes."""
    # The 60 s bound per call keeps this file's teardowns inside the suite's 900 s cleanup budget.
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
