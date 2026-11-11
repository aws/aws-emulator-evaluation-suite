"""delete-report-definition-clears-tags-for-recreated-same-name."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-report-definition-clears-tags-for-recreated-same-name"
GROUP = 'tags'
SERVICES = ['cur']


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A report's tags are an association with its current lifetime, not with its name:
    deleting it and creating a new report under the same name starts that name untagged.
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
    report_definition = {
        "ReportName": report_name,
        "TimeUnit": "DAILY",
        "Format": "textORcsv",
        "Compression": "GZIP",
        "AdditionalSchemaElements": ["RESOURCES"],
        "S3Bucket": bucket,
        "S3Prefix": "cur-reports",
        "S3Region": ctx.region,
    }

    cur.put_report_definition(ReportDefinition=report_definition)
    ctx.on_cleanup(lambda: cur.delete_report_definition(ReportName=report_name))
    cur.tag_resource(
        ReportName=report_name,
        Tags=[{"Key": "env", "Value": "staging"}, {"Key": "owner", "Value": "finops"}],
    )
    before = cur.list_tags_for_resource(ReportName=report_name)["Tags"]
    assert len(before) == 2, f"expected 2 tags before delete, got {before!r}"

    cur.delete_report_definition(ReportName=report_name)
    cur.put_report_definition(ReportDefinition=report_definition)

    after = cur.list_tags_for_resource(ReportName=report_name)["Tags"]
    assert after == [], f"recreating {report_name!r} should start untagged, got {after!r}"

    # positive control: the recreated report is fully functional, not merely empty-tagged.
    cur.tag_resource(ReportName=report_name, Tags=[{"Key": "env", "Value": "production"}])
    control = cur.list_tags_for_resource(ReportName=report_name)["Tags"]
    assert control == [{"Key": "env", "Value": "production"}], (
        f"the recreated report should accept a fresh tag, got {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
