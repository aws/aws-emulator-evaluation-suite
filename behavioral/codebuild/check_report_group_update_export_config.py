"""report-group-update-export-config."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

def _create_report_group(cb, ctx, tags=None):
    """Create a uniquely-named TEST report group; register teardown; return its reportGroup dict."""
    kwargs = {"name": ctx.unique_name("sim2real-behav-rg-"), "type": "TEST",
              "exportConfig": {"exportConfigType": "NO_EXPORT"}}
    if tags is not None:
        kwargs["tags"] = tags
    rg = cb.create_report_group(**kwargs)["reportGroup"]
    ctx.on_cleanup(lambda: cb.delete_report_group(arn=rg["arn"], deleteReports=True))
    return rg


def _create_export_bucket(ctx):
    """Create a uniquely-named, tagged S3 bucket to use as an export destination; register teardown."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-rg-export-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    # us-east-1 is CreateBucket's own default region; passing a LocationConstraint
    # for it is rejected with InvalidLocationConstraint, so it must be omitted only there.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "report-group-update-export-config"}]},
    )
    return name


def _delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


CHECK = "report-group-update-export-config"
GROUP = 'lifecycle'
SERVICES = ['codebuild']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateReportGroup switches exportConfig from NO_EXPORT to an S3 destination with a stable
    ARN, confirmed by an independent BatchGetReportGroups read, not just the update's echo."""
    cb = ctx.client("codebuild")
    rg = _create_report_group(cb, ctx)
    arn = rg["arn"]
    assert rg["exportConfig"]["exportConfigType"] == "NO_EXPORT", rg

    bucket = _create_export_bucket(ctx)
    resp = cb.update_report_group(
        arn=arn,
        exportConfig={
            "exportConfigType": "S3",
            "s3Destination": {
                "bucket": bucket,
                "path": "reports",
                "packaging": "NONE",
                "encryptionDisabled": True,
            },
        },
    )
    updated = resp["reportGroup"]
    assert updated["arn"] == arn, updated
    assert updated["exportConfig"]["exportConfigType"] == "S3", updated
    assert updated["exportConfig"]["s3Destination"]["bucket"] == bucket, updated

    got = cb.batch_get_report_groups(reportGroupArns=[arn])
    found = {g["arn"]: g for g in got.get("reportGroups", [])}
    assert arn in found, got
    persisted = found[arn]["exportConfig"]
    assert persisted["exportConfigType"] == "S3", persisted
    assert persisted["s3Destination"]["bucket"] == bucket, persisted
    assert persisted["s3Destination"]["packaging"] == "NONE", persisted


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
