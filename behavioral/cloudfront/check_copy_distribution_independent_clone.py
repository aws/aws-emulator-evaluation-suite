"""copy-distribution-independent-clone."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "copy-distribution-independent-clone"
GROUP = "state-machine"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_DEPLOY_TIMEOUT_S = 1200.0
_DEPLOY_INTERVAL_S = 20.0


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyDistribution yields an independent resource: distinct identity, and later edits don't leak back."""
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-cf-copy-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    # S3 rejects a LocationConstraint of "us-east-1" outright (it is the implicit default), so this
    # literal is S3's own API quirk, not a region pin on the check.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    original_comment = "sim2real-behav original"
    primary = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-primary-"),
            "Comment": original_comment,
            "Enabled": False,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "origin1",
                        "DomainName": f"{bucket}.s3.amazonaws.com",
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "origin1",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
            },
        }
    )
    primary_id = primary["Distribution"]["Id"]
    primary_arn = primary["Distribution"]["ARN"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, primary_id))
    cf.tag_resource(Resource=primary_arn, Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})

    primary_cfg = cf.get_distribution_config(Id=primary_id)
    copy = cf.copy_distribution(
        PrimaryDistributionId=primary_id,
        IfMatch=primary_cfg["ETag"],
        Staging=True,
        CallerReference=ctx.unique_name("sim2real-staging-"),
        Enabled=False,
    )
    staging_id = copy["Distribution"]["Id"]
    staging_arn = copy["Distribution"]["ARN"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, staging_id))
    cf.tag_resource(Resource=staging_arn, Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})

    assert staging_id != primary_id, "the copy must have its own distribution Id"
    assert copy["Distribution"]["ARN"] != primary_arn, "the copy must have its own ARN"
    assert copy["Distribution"]["DomainName"] != primary["Distribution"]["DomainName"], (
        f"the copy must have its own DomainName, got the primary's {primary['Distribution']['DomainName']!r} on both"
    )
    assert copy["Distribution"]["DistributionConfig"]["Comment"] == original_comment, (
        "the clone must start with the primary's config content"
    )

    # Mutate the clone only; the primary's config must remain untouched (true decoupling).
    staging_cfg = cf.get_distribution_config(Id=staging_id)
    mutated = staging_cfg["DistributionConfig"]
    mutated["Comment"] = "sim2real-behav clone-only-edit"
    cf.update_distribution(Id=staging_id, IfMatch=staging_cfg["ETag"], DistributionConfig=mutated)

    reread_staging = cf.get_distribution_config(Id=staging_id)["DistributionConfig"]
    assert reread_staging["Comment"] == "sim2real-behav clone-only-edit", (
        f"expected the clone's own edit to stick, got Comment={reread_staging['Comment']!r}"
    )

    reread_primary = cf.get_distribution_config(Id=primary_id)["DistributionConfig"]
    assert reread_primary["Comment"] == original_comment, "editing the clone must not affect the primary"


def _disable_and_delete_distribution(ctx, dist_id: str, timeout_s: float = _DEPLOY_TIMEOUT_S) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg = cf.get_distribution_config(Id=dist_id)
    except cf.exceptions.NoSuchDistribution:
        return
    etag = cfg["ETag"]
    conf = cfg["DistributionConfig"]
    if conf.get("Enabled"):
        conf["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=conf)["ETag"]
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        status = got["Distribution"]["Status"]
        etag = got["ETag"]
        if status == "Deployed":
            break
        time.sleep(_DEPLOY_INTERVAL_S)
    if status != "Deployed":
        raise AssertionError(f"distribution {dist_id} never reached Deployed for cleanup (last={status})")
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
