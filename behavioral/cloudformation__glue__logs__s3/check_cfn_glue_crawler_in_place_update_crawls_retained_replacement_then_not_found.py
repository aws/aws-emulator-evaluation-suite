"""cfn-glue-crawler-in-place-update-crawls-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-glue-crawler-in-place-update-crawls-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue", "logs", "s3"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A crawl of one small object, stopping phase included, takes a few minutes.
_CRAWL_S = 600.0
#: A role reaches Glue within seconds; the bound only stops a retry loop.
_TRUST_S = 120.0
#: A change or delete reaches every read within seconds; the bound only stops a hung poll.
_PROPAGATE_S = 60.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1500.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_IAM = ["CAPABILITY_IAM"]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: CreateCrawler's refusal of a role Glue cannot assume yet; CreateStack is retried on it only.
_NOT_ASSUMABLE = "Service is unable to assume provided role"
#: StopCrawler's refusal of a crawler whose crawl has already ended; {name} is the crawler.
_NOT_RUNNING = ("CrawlerNotRunningException", "Crawler with name {name} is not running")
#: GetCrawler's and DeleteCrawler's refusal of a crawler that does not exist; {name} is the crawler.
_NO_CRAWLER = ("EntityNotFoundException", "Crawler entry with name {name} does not exist")
#: DeleteLogStream's refusal of a log stream that does not exist.
_NO_STREAM = ("ResourceNotFoundException", "The specified log stream does not exist.")
#: S3's refusal of a bucket that does not exist.
_NO_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")
_DATA_KEY = "data/rows.json"
_ROWS = b'{"id": 1, "name": "alpha"}\n{"id": 2, "name": "beta"}\n'
_SCHEMA_POLICY = {"UpdateBehavior": "UPDATE_IN_DATABASE", "DeleteBehavior": "LOG"}


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::Glue::Crawler survives create, in-place update, retained replacement and delete.

    GetCrawler reads back each template; after TablePrefix changes in place a crawl of the S3
    target creates the prefixed JSON table, and a Name change under Retain keeps the old crawler.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-crawler.html
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    logs = ctx.client("logs")

    bucket = ctx.unique_name("sim2real-cfnreal-gc-").lower().replace("_", "-")
    stack_name = ctx.unique_name("sim2real-cfnreal-gc-")
    database = ctx.unique_name("sim2real_cfnreal_gc_").lower().replace("-", "_")
    crawler_v1 = ctx.unique_name("sim2real-cfnreal-gc-a-")
    crawler_v2 = ctx.unique_name("sim2real-cfnreal-gc-b-")
    target = f"s3://{bucket}/data/"

    # LIFO: a running crawl stops, the stack goes, then the retained crawler, its log stream
    # and the bucket. Teardown waits share one deadline of their own.
    limit: dict = {}
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket))
    ctx.on_cleanup(lambda: _delete_log_streams(logs, crawler_v1))
    ctx.on_cleanup(lambda: _delete_crawler(glue, crawler_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name, limit))
    ctx.on_cleanup(lambda: _stop_crawler(glue, crawler_v1, limit))
    # us-east-1 is the one region whose CreateBucket takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    s3.put_object(Bucket=bucket, Key=_DATA_KEY, Body=_ROWS)

    # ---- 1. create: CloudFormation view, Glue view ---------------------------------------------
    stack_id = _create_retrying_role(
        ctx, cfn, stack_name, _template(crawler_v1, database, bucket, "first_")
    )
    _assert_tracks(cfn, stack_id, "Crawler", crawler_v1)
    _assert_tracks(cfn, stack_id, "Database", database)
    role_arn = _outputs(cfn, stack_id)["RoleArn"]
    _assert_crawler(_crawler(glue, crawler_v1), crawler_v1, role_arn, database, target, "first_")

    # ---- 2. in place: TablePrefix and Description, then a crawl creates the prefixed table -----
    body = _template(crawler_v1, database, bucket, "second_")
    rows = _update(ctx, cfn, stack_id, "Crawler", body, Capabilities=_IAM)
    _assert_updated_in_place(rows, crawler_v1)
    crawler = _poll(
        ctx,
        lambda: _crawler(glue, crawler_v1),
        lambda c: c.get("TablePrefix") == "second_",
        cap_s=_PROPAGATE_S,
        what=f"GetCrawler on {crawler_v1} to read the updated TablePrefix",
    )
    _assert_crawler(crawler, crawler_v1, role_arn, database, target, "second_")

    glue.start_crawler(Name=crawler_v1)
    crawled = _poll(
        ctx,
        lambda: _crawler(glue, crawler_v1),
        lambda c: c["State"] == "READY" and "LastCrawl" in c,
        cap_s=_CRAWL_S,
        interval_s=5.0,
        what=f"crawler {crawler_v1} to finish its first crawl",
    )
    last = crawled["LastCrawl"]
    assert last["Status"] == "SUCCEEDED", f"the crawl must succeed, got {last!r}"
    tables = glue.get_tables(DatabaseName=database)["TableList"]
    got = [
        (
            t["Name"],
            t.get("Parameters", {}).get("classification"),
            t["StorageDescriptor"].get("Location"),
            t["StorageDescriptor"].get("Columns"),
        )
        for t in tables
    ]
    assert got == [
        (
            "second_data",
            "json",
            target,
            [{"Name": "id", "Type": "int"}, {"Name": "name", "Type": "string"}],
        )
    ], f"the crawl must create one JSON table named for the folder with the new prefix: {got!r}"

    # ---- 3. Name forces replacement; UpdateReplacePolicy Retain keeps the old crawler ----------
    body = _template(crawler_v2, database, bucket, "second_")
    rows = _update(ctx, cfn, stack_id, "Crawler", body, Capabilities=_IAM)
    _assert_replaced_and_retained(rows, crawler_v1, crawler_v2)
    _assert_tracks(cfn, stack_id, "Crawler", crawler_v2)
    _assert_crawler(_crawler(glue, crawler_v2), crawler_v2, role_arn, database, target, "second_")
    _assert_crawler(_crawler(glue, crawler_v1), crawler_v1, role_arn, database, target, "second_")

    # ---- 4. DeleteStack: the crawler it owns is gone, the retained one stays -------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    want = ("EntityNotFoundException", f"Crawler entry with name {crawler_v2} does not exist")
    _await_error(ctx, lambda: glue.get_crawler(Name=crawler_v2), want, "GetCrawler after delete")
    assert _crawler(glue, crawler_v1)["Name"] == crawler_v1, "the retained crawler survives"


def _description(prefix: str) -> str:
    return f"reality check crawler, prefix {prefix}"


def _template(name: str, database: str, bucket: str, prefix: str) -> str:
    bucket_arn = f"arn:${{AWS::Partition}}:s3:::{bucket}"
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Database": {
                    "Type": "AWS::Glue::Database",
                    "Properties": {
                        "CatalogId": {"Ref": "AWS::AccountId"},
                        "DatabaseInput": {"Name": database},
                    },
                },
                "CrawlerRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "glue.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            {
                                "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/"
                                "service-role/AWSGlueServiceRole"
                            }
                        ],
                        "Policies": [
                            {
                                "PolicyName": "bucket",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["s3:GetObject", "s3:ListBucket"],
                                            "Resource": [
                                                {"Fn::Sub": bucket_arn},
                                                {"Fn::Sub": f"{bucket_arn}/*"},
                                            ],
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Crawler": {
                    "Type": "AWS::Glue::Crawler",
                    # Name is create-only, so a new name replaces the crawler.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": name,
                        "Description": _description(prefix),
                        "Role": {"Fn::GetAtt": ["CrawlerRole", "Arn"]},
                        "DatabaseName": {"Ref": "Database"},
                        "TablePrefix": prefix,
                        "Targets": {"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
                        "SchemaChangePolicy": _SCHEMA_POLICY,
                    },
                },
            },
            "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["CrawlerRole", "Arn"]}}},
        }
    )


def _crawler(glue, name: str) -> dict:
    return glue.get_crawler(Name=name)["Crawler"]


def _assert_crawler(
    crawler: dict, name: str, role_arn: str, database: str, target: str, prefix: str
) -> None:
    """Glue's view: GetCrawler carries exactly the template's settings.

    GetCrawler returns Role as the role's name, though the template passes its ARN.
    """
    got = {
        "Name": crawler.get("Name"),
        "Description": crawler.get("Description"),
        "Role": crawler.get("Role"),
        "DatabaseName": crawler.get("DatabaseName"),
        "TablePrefix": crawler.get("TablePrefix"),
        "S3Targets": [t.get("Path") for t in crawler.get("Targets", {}).get("S3Targets", [])],
        "SchemaChangePolicy": crawler.get("SchemaChangePolicy"),
    }
    want = {
        "Name": name,
        "Description": _description(prefix),
        "Role": role_arn.rsplit("/", 1)[1],
        "DatabaseName": database,
        "TablePrefix": prefix,
        "S3Targets": [target],
        "SchemaChangePolicy": _SCHEMA_POLICY,
    }
    assert got == want, f"GetCrawler must read back the template: {got!r}, want {want!r}"


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o.get("OutputValue") for o in _stack(cfn, stack_id).get("Outputs", [])}


def _create_retrying_role(ctx, cfn, stack_name: str, body: str) -> str:
    """CreateStack until CREATE_COMPLETE and return the StackId.

    A fresh role can reach Glue only seconds after IAM returns it, and no read shows when; a
    rollback for exactly that reason is deleted and created again, within _TRUST_S.
    """
    deadline = time.monotonic() + _budget_s(ctx, _TRUST_S)
    while True:
        stack_id = cfn.create_stack(
            StackName=stack_name, Capabilities=_IAM, Tags=_TAGS, TemplateBody=body
        )["StackId"]
        created = _settle(ctx, cfn, stack_id)
        if created["StackStatus"] == "CREATE_COMPLETE":
            return stack_id
        reasons = [
            e.get("ResourceStatusReason") or ""
            for e in _events(cfn, stack_id)
            if e["LogicalResourceId"] == "Crawler" and e["ResourceStatus"] == "CREATE_FAILED"
        ]
        retry = (
            created["StackStatus"] == "ROLLBACK_COMPLETE"
            and len(reasons) == 1
            and _NOT_ASSUMABLE in reasons[0]
            and time.monotonic() < deadline
        )
        assert retry, (
            f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}; "
            f"Crawler failures {reasons!r}"
        )
        _delete_and_confirm(ctx, cfn, stack_id)
        time.sleep(5.0)


def _stop_crawler(glue, name: str, limit: dict) -> None:
    """Teardown: stop a crawl still running and wait until the crawler is READY."""
    try:
        state = _crawler(glue, name)["State"]
        if state == "RUNNING":
            glue.stop_crawler(Name=name)
    except ClientError as exc:
        if _error(exc) in (_named(_NO_CRAWLER, name), _named(_NOT_RUNNING, name)):
            return
        raise
    if state != "READY":
        _poll(
            None,
            lambda: _crawler(glue, name)["State"],
            lambda s: s == "READY",
            cap_s=_remaining(limit),
            interval_s=5.0,
            what=f"crawler {name} to stop",
        )


def _delete_crawler(glue, name: str) -> None:
    try:
        glue.delete_crawler(Name=name)
    except ClientError as exc:
        if _error(exc) != _named(_NO_CRAWLER, name):
            raise


def _error(exc: ClientError) -> tuple:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def _named(pair: tuple[str, str], name: str) -> tuple[str, str]:
    return pair[0], pair[1].format(name=name)


def _delete_log_streams(logs, prefix: str) -> None:
    """Teardown: delete the streams named prefix* that Glue wrote into /aws-glue/ log groups.

    The groups are account-shared, so they stay.
    """
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix="/aws-glue/"):
        for group in page["logGroups"]:
            name = group["logGroupName"]
            for streams in logs.get_paginator("describe_log_streams").paginate(
                logGroupName=name, logStreamNamePrefix=prefix
            ):
                for stream in streams.get("logStreams", []):
                    try:
                        logs.delete_log_stream(
                            logGroupName=name, logStreamName=stream["logStreamName"]
                        )
                    except ClientError as exc:
                        if _error(exc) != _NO_STREAM:
                            raise


def _empty_bucket(s3, bucket: str) -> None:
    """Delete every object version and delete marker; a bucket already gone is fine."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    except ClientError as exc:
        if _error(exc) != _NO_BUCKET:
            raise


def _drop_bucket(s3, bucket: str) -> None:
    _empty_bucket(s3, bucket)
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if _error(exc) != _NO_BUCKET:
            raise


def _await_error(ctx, fn, want: tuple[str, str], what: str) -> None:
    """Poll fn until it is refused, then assert the exact (code, message) want.

    A delete reaches every read within seconds, so a call that still succeeds is retried.
    """
    timeout_s = _budget_s(ctx, _PROPAGATE_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message") or "")
            assert got == want, f"{what}: {got!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while {what} still succeeded; not graded")
            raise AssertionError(f"{what} still succeeded after {timeout_s:.0f}s: {result!r}")
        time.sleep(2.0)


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    Teardown passes ctx=None and keeps the fixed cap: the runner's deadline does not cover it.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _remaining(limit: dict) -> float:
    """Seconds left of the one teardown deadline, which starts at the first teardown wait."""
    deadline = limit.setdefault("at", time.monotonic() + _TEARDOWN_CAP_S)
    return max(1.0, deadline - time.monotonic())


def _delete_stack(cfn, stack_name: str, limit: dict) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_remaining(limit),
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_remaining(limit),
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
