"""bucket-metrics-configuration-filter-prefix-and-tag-combo."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "bucket-metrics-configuration-filter-prefix-and-tag-combo"
GROUP = "telemetry"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A metrics filter combining a prefix and tags under And reads back under And with both
    predicates intact, not flattened onto top-level Prefix/Tag predicates."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    config_id = "cfg-and-combo"
    tags = [
        {"Key": "project", "Value": "alpha"},
        {"Key": "env", "Value": "prod"},
    ]
    s3.put_bucket_metrics_configuration(
        Bucket=bucket,
        Id=config_id,
        MetricsConfiguration={
            "Id": config_id,
            "Filter": {
                "And": {
                    "Prefix": "combo/",
                    "Tags": tags,
                }
            },
        },
    )
    ctx.on_cleanup(
        lambda: s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=config_id)
    )

    got = s3.get_bucket_metrics_configuration(Bucket=bucket, Id=config_id)
    metrics_cfg = got["MetricsConfiguration"]
    assert metrics_cfg["Id"] == config_id, metrics_cfg

    filt = metrics_cfg["Filter"]
    # AND semantics must be preserved under the And conjunction, not
    # flattened onto top-level Prefix/Tag predicates.
    assert "Prefix" not in filt, filt
    assert "Tag" not in filt, filt
    assert "And" in filt, filt

    and_op = filt["And"]
    assert and_op.get("Prefix") == "combo/", and_op
    got_tags = and_op.get("Tags", [])
    assert {(t["Key"], t["Value"]) for t in got_tags} == {
        (t["Key"], t["Value"]) for t in tags
    }, got_tags
    assert len(got_tags) == len(tags), got_tags


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
