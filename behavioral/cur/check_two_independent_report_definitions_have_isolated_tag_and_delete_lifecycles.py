"""two-independent-report-definitions-have-isolated-tag-and-delete-lifecycles."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "two-independent-report-definitions-have-isolated-tag-and-delete-lifecycles"
GROUP = 'isolation'
SERVICES = ['cur']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_bucket(s3, bucket: str) -> None:
    objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    for obj in objs:
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _billing_reports_policy(bucket: str, account: str) -> str:
    condition = {
        "StringEquals": {"aws:SourceAccount": account},
        "StringLike": {"aws:SourceArn": f"arn:aws:cur:us-east-1:{account}:definition/*"},
    }
    return json.dumps({
        "Version": "2008-10-17",
        "Statement": [
            {
                "Sid": "AllowBillingReportsAcl",
                "Effect": "Allow",
                "Principal": {"Service": "billingreports.amazonaws.com"},
                "Action": ["s3:GetBucketAcl", "s3:GetBucketPolicy"],
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": condition,
            },
            {
                "Sid": "AllowBillingReportsPut",
                "Effect": "Allow",
                "Principal": {"Service": "billingreports.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": condition,
            },
        ],
    })


def _find_report(cur, name: str) -> dict | None:
    """The report ``name`` names, read through every page (the account-wide listing has no filter)."""
    token = None
    while True:
        kwargs = {"MaxResults": 5}
        if token:
            kwargs["NextToken"] = token
        page = cur.describe_report_definitions(**kwargs)
        for report in page["ReportDefinitions"]:
            if report["ReportName"] == name:
                return report
        token = page.get("NextToken")
        if not token:
            return None


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two report definitions in the same account are independent resources: tagging one
    and deleting the other leaves the untouched one's tags and existence unaffected.
    """
    cur = ctx.client("cur", region="us-east-1")
    s3 = ctx.client("s3", region=ctx.region)

    bucket = ctx.unique_name("sim2real-behav-cur-bkt-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(_teardown(lambda: _delete_bucket(s3, bucket), "NoSuchBucket"))
    s3.put_bucket_policy(Bucket=bucket, Policy=_billing_reports_policy(bucket, ctx.account))

    name_a = ctx.unique_name("sim2real-behav-cur-a-")
    name_b = ctx.unique_name("sim2real-behav-cur-b-")

    def definition(name: str, prefix: str) -> dict:
        return {
            "ReportName": name,
            "TimeUnit": "DAILY",
            "Format": "textORcsv",
            "Compression": "GZIP",
            "AdditionalSchemaElements": ["RESOURCES"],
            "S3Bucket": bucket,
            "S3Prefix": prefix,
            "S3Region": ctx.region,
        }

    cur.put_report_definition(ReportDefinition=definition(name_a, "cur-reports-a"))
    ctx.on_cleanup(lambda: cur.delete_report_definition(ReportName=name_a))
    cur.put_report_definition(ReportDefinition=definition(name_b, "cur-reports-b"))

    cur.tag_resource(ReportName=name_a, Tags=[{"Key": "owner", "Value": "finops"}])
    tags_a = cur.list_tags_for_resource(ReportName=name_a)["Tags"]
    tags_b = cur.list_tags_for_resource(ReportName=name_b)["Tags"]
    assert tags_a == [{"Key": "owner", "Value": "finops"}], f"unexpected tags on A: {tags_a!r}"
    assert tags_b == [], f"tagging A must not tag B, got {tags_b!r}"

    cur.delete_report_definition(ReportName=name_b)

    code, message = _error(lambda: cur.list_tags_for_resource(ReportName=name_b))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for B, got {code}"
    assert message == "", f"expected an empty message, got {message!r}"

    survivor = _find_report(cur, name_a)
    assert survivor is not None, f"deleting B must not delete A, but {name_a!r} is gone"
    survivor_tags = cur.list_tags_for_resource(ReportName=name_a)["Tags"]
    assert survivor_tags == [{"Key": "owner", "Value": "finops"}], (
        f"deleting B must not change A's tags, got {survivor_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
