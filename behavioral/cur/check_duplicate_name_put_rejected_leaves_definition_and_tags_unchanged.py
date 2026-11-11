"""duplicate-name-put-rejected-leaves-definition-and-tags-unchanged."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-name-put-rejected-leaves-definition-and-tags-unchanged"
GROUP = 'conflicts'
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutReportDefinition under a name that already has a different definition is rejected
    as a duplicate, and the rejection leaves both the definition and its tags untouched.
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

    report_name = ctx.unique_name("sim2real-behav-cur-")

    def definition(time_unit: str) -> dict:
        return {
            "ReportName": report_name,
            "TimeUnit": time_unit,
            "Format": "textORcsv",
            "Compression": "GZIP",
            "AdditionalSchemaElements": ["RESOURCES"],
            "S3Bucket": bucket,
            "S3Prefix": "cur-reports",
            "S3Region": ctx.region,
        }

    cur.put_report_definition(ReportDefinition=definition("DAILY"))
    ctx.on_cleanup(lambda: cur.delete_report_definition(ReportName=report_name))
    cur.tag_resource(ReportName=report_name, Tags=[{"Key": "env", "Value": "staging"}])

    code, message = _error(
        lambda: cur.put_report_definition(ReportDefinition=definition("MONTHLY"))
    )
    assert code == "DuplicateReportNameException", f"expected DuplicateReportNameException, got {code}"
    assert message == "", f"expected an empty message, got {message!r}"

    survivor = _find_report(cur, report_name)
    assert survivor is not None, f"{report_name!r} disappeared after the rejected duplicate put"
    assert survivor["TimeUnit"] == "DAILY", (
        f"the rejected duplicate put must not change the definition, got TimeUnit {survivor['TimeUnit']!r}"
    )

    survivor_tags = cur.list_tags_for_resource(ReportName=report_name)["Tags"]
    assert survivor_tags == [{"Key": "env", "Value": "staging"}], (
        f"the rejected duplicate put must not change tags, got {survivor_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
