"""bucket-metrics-configuration-delete-reflected-in-list-then-get-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "bucket-metrics-configuration-delete-reflected-in-list-then-get-rejected"
GROUP = "telemetry"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting one of two metrics configurations removes it from ListBucketMetricsConfigurations,
    leaves the other intact, and a Get on the deleted Id fails NoSuchConfiguration."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    id_keep = "cfg-keep"
    id_drop = "cfg-drop"

    s3.put_bucket_metrics_configuration(
        Bucket=bucket,
        Id=id_keep,
        MetricsConfiguration={"Id": id_keep, "Filter": {"Prefix": "keep/"}},
    )
    ctx.on_cleanup(
        lambda: s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=id_keep)
    )

    s3.put_bucket_metrics_configuration(
        Bucket=bucket,
        Id=id_drop,
        MetricsConfiguration={"Id": id_drop, "Filter": {"Prefix": "drop/"}},
    )

    before = s3.list_bucket_metrics_configurations(Bucket=bucket)
    before_ids = {c["Id"] for c in before.get("MetricsConfigurationList", [])}
    assert {id_keep, id_drop} <= before_ids, before_ids

    s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=id_drop)

    after = s3.list_bucket_metrics_configurations(Bucket=bucket)
    after_ids = {c["Id"] for c in after.get("MetricsConfigurationList", [])}

    assert id_drop not in after_ids, after_ids
    assert id_keep in after_ids, after_ids

    by_id = {c["Id"]: c for c in after.get("MetricsConfigurationList", [])}
    assert by_id[id_keep]["Filter"].get("Prefix") == "keep/", by_id[id_keep]

    from botocore.exceptions import ClientError

    try:
        s3.get_bucket_metrics_configuration(Bucket=bucket, Id=id_drop)
        raise AssertionError(
            "expected GetBucketMetricsConfiguration for a deleted Id to fail"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NoSuchConfiguration", exc.response["Error"]
        message = exc.response["Error"].get("Message")
        assert message == "The specified configuration does not exist.", message


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-s3metrics-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
