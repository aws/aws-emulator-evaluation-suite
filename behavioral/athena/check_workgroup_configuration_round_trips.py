"""workgroup-configuration-round-trips."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "workgroup-configuration-round-trips"
GROUP = 'workgroup'
SERVICES = ['athena']

def _empty_and_delete_bucket(s3, bucket):
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _output_location(ctx):
    """Create an Athena query-results bucket (region-correct) and return its s3:// prefix."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-results-")
    kwargs = {"Bucket": bucket}
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 (it is the
    # implicit default region); every other region must name itself.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return f"s3://{bucket}/results/"

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """WorkGroup Configuration fields round-trip exactly and are independently patchable via UpdateWorkGroup."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-cfg-")
    output_loc = _output_location(ctx)
    athena.create_work_group(
        Name=wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": output_loc},
            "BytesScannedCutoffPerQuery": 10_000_000,
            "EnforceWorkGroupConfiguration": True,
            "PublishCloudWatchMetricsEnabled": False,
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    cfg = athena.get_work_group(WorkGroup=wg)["WorkGroup"]["Configuration"]
    assert cfg["ResultConfiguration"]["OutputLocation"] == output_loc, (
        f"expected OutputLocation {output_loc!r}, got {cfg['ResultConfiguration'].get('OutputLocation')!r}"
    )
    assert cfg["BytesScannedCutoffPerQuery"] == 10_000_000, (
        f"expected BytesScannedCutoffPerQuery 10000000, got {cfg.get('BytesScannedCutoffPerQuery')!r}"
    )
    assert cfg["EnforceWorkGroupConfiguration"] is True, (
        f"expected EnforceWorkGroupConfiguration True, got {cfg.get('EnforceWorkGroupConfiguration')!r}"
    )
    assert cfg["PublishCloudWatchMetricsEnabled"] is False, (
        f"expected PublishCloudWatchMetricsEnabled False, got {cfg.get('PublishCloudWatchMetricsEnabled')!r}"
    )

    athena.update_work_group(
        WorkGroup=wg,
        ConfigurationUpdates={
            "BytesScannedCutoffPerQuery": 20_000_000,
            "PublishCloudWatchMetricsEnabled": True,
        },
    )
    cfg = athena.get_work_group(WorkGroup=wg)["WorkGroup"]["Configuration"]
    assert cfg["BytesScannedCutoffPerQuery"] == 20_000_000, "BytesScannedCutoffPerQuery update did not apply"
    assert cfg["PublishCloudWatchMetricsEnabled"] is True, "PublishCloudWatchMetricsEnabled update did not apply"
    assert cfg["ResultConfiguration"]["OutputLocation"] == output_loc, (
        "unrelated field must not be clobbered by a partial ConfigurationUpdates"
    )
    assert cfg["EnforceWorkGroupConfiguration"] is True, (
        "unrelated field EnforceWorkGroupConfiguration must not be clobbered by a partial ConfigurationUpdates"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
