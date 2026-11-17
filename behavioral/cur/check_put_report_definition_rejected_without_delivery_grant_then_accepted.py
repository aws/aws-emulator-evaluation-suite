"""put-report-definition-rejected-without-delivery-grant-then-accepted."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-report-definition-rejected-without-delivery-grant-then-accepted"
GROUP = "report-definition"
SERVICES = ["cur", "s3"]

# The CUR control plane answers only from this region, whatever region the report's own
# S3 bucket and delivered data live in.
_CUR_REGION = "us-east-1"


def _refusal(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises too."""
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


def _empty_and_delete_bucket(s3, bucket):
    def run_undo() -> None:
        try:
            for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchBucket":
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutReportDefinition refuses a bucket with no billingreports.amazonaws.com delivery grant,
    and the identical request succeeds once the grant is added, with DescribeReportDefinitions
    then showing exactly the fields the request named.
    """
    s3 = ctx.client("s3", region=ctx.region)
    cur = ctx.client("cur", region=_CUR_REGION)

    bucket = ctx.unique_name("sim2real-cur-bucket-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(_empty_and_delete_bucket(s3, bucket))

    report_name = ctx.unique_name("sim2real-cur-report-")
    report_definition = {
        "ReportName": report_name,
        "TimeUnit": "DAILY",
        "Format": "textORcsv",
        "Compression": "GZIP",
        "AdditionalSchemaElements": ["RESOURCES"],
        "S3Bucket": bucket,
        "S3Prefix": "sim2real-cur-prefix",
        "S3Region": ctx.region,
    }

    expected_refusal = (
        "ValidationException",
        f"Failed to verify customer bucket permission. accountId= {ctx.account}, "
        f"bucket name: {bucket}, bucket region: {ctx.region}",
    )
    refusal = _refusal(lambda: cur.put_report_definition(ReportDefinition=dict(report_definition)))
    assert refusal == expected_refusal, f"expected {expected_refusal!r}, got {refusal!r}"

    # Effect absent: the rejected request left no report definition behind.
    before = {r["ReportName"] for r in cur.describe_report_definitions()["ReportDefinitions"]}
    assert report_name not in before, f"a rejected PutReportDefinition still created {report_name!r}"

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "billingreports.amazonaws.com"},
                "Action": ["s3:GetBucketAcl", "s3:GetBucketPolicy"],
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": f"arn:aws:cur:{_CUR_REGION}:{ctx.account}:definition/*",
                        "aws:SourceAccount": ctx.account,
                    }
                },
            },
            {
                "Effect": "Allow",
                "Principal": {"Service": "billingreports.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": f"arn:aws:cur:{_CUR_REGION}:{ctx.account}:definition/*",
                        "aws:SourceAccount": ctx.account,
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket_policy(Bucket=bucket), "NoSuchBucket"))

    # The identical request, with nothing but the bucket's delivery grant changed, now succeeds.
    cur.put_report_definition(ReportDefinition=dict(report_definition))
    ctx.on_cleanup(
        _teardown(lambda: cur.delete_report_definition(ReportName=report_name), "ResourceNotFoundException")
    )

    after = {r["ReportName"]: r for r in cur.describe_report_definitions()["ReportDefinitions"]}
    assert report_name in after, (
        f"PutReportDefinition succeeded but {report_name!r} is absent from DescribeReportDefinitions"
    )
    created = after[report_name]
    for field, expected in report_definition.items():
        assert created[field] == expected, f"{field}: expected {expected!r}, got {created[field]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
