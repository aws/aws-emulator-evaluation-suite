"""bucket-metrics-configuration-multi-filter-listing."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "bucket-metrics-configuration-multi-filter-listing"
GROUP = "telemetry"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Multiple metrics configurations with distinct filter predicates are all
    returned by ListBucketMetricsConfigurations with correct filter fields and
    no duplication."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    id_prefix = "cfg-prefix"
    id_tag = "cfg-tag"
    id_none = "cfg-nofilter"

    s3.put_bucket_metrics_configuration(
        Bucket=bucket,
        Id=id_prefix,
        MetricsConfiguration={"Id": id_prefix, "Filter": {"Prefix": "logs/"}},
    )
    ctx.on_cleanup(
        lambda: s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=id_prefix)
    )

    s3.put_bucket_metrics_configuration(
        Bucket=bucket,
        Id=id_tag,
        MetricsConfiguration={
            "Id": id_tag,
            "Filter": {"Tag": {"Key": "project", "Value": "alpha"}},
        },
    )
    ctx.on_cleanup(
        lambda: s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=id_tag)
    )

    s3.put_bucket_metrics_configuration(
        Bucket=bucket,
        Id=id_none,
        MetricsConfiguration={"Id": id_none},
    )
    ctx.on_cleanup(
        lambda: s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=id_none)
    )

    listing = s3.list_bucket_metrics_configurations(Bucket=bucket)
    configs = listing.get("MetricsConfigurationList", [])
    ids = [c["Id"] for c in configs]

    # no duplication: each id appears exactly once
    assert ids.count(id_prefix) == 1, ids
    assert ids.count(id_tag) == 1, ids
    assert ids.count(id_none) == 1, ids
    assert len(configs) == 3, configs

    by_id = {c["Id"]: c for c in configs}

    prefix_filter = by_id[id_prefix]["Filter"]
    assert prefix_filter.get("Prefix") == "logs/", prefix_filter
    assert "Tag" not in prefix_filter and "And" not in prefix_filter, (
        f"prefix-only filter must not gain a Tag/And predicate: {prefix_filter}"
    )

    tag_filter = by_id[id_tag]["Filter"]
    assert tag_filter.get("Tag") == {"Key": "project", "Value": "alpha"}, tag_filter
    assert "Prefix" not in tag_filter and "And" not in tag_filter, (
        f"tag-only filter must not gain a Prefix/And predicate: {tag_filter}"
    )

    # a filter-less config either omits Filter entirely or omits its predicates
    nofilter_cfg = by_id[id_none]
    if "Filter" in nofilter_cfg:
        f = nofilter_cfg["Filter"]
        assert not f.get("Prefix") and not f.get("Tag") and not f.get("And"), f


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-s3metrics-")
    kwargs = {"Bucket": name}
    # us-east-1 is S3's region-less default: CreateBucketConfiguration must be omitted there
    # or the call is rejected, so this literal names that special case, not a pinned region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]}
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
