"""obs-cloudfront-3-standard-logging-to-acl-disabled-bucket-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "obs-cloudfront-3-standard-logging-to-acl-disabled-bucket-rejected"
GROUP = "log-delivery"
SERVICES = ["cloudfront", "s3"]

# On AWS, CreateDistribution with Logging.Enabled=true naming a
# bucket whose ObjectOwnership is BucketOwnerEnforced (ACLs disabled) is refused with HTTP 400
# InvalidArgument "The S3 bucket that you specified for CloudFront logs does not enable ACL access:
# <bucket>.s3.amazonaws.com". Nothing in the CloudFront model ties LoggingConfig.Bucket to the S3
# bucket's ownership controls — CloudFront reads that state ACROSS the service boundary.

MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

_TAGS = [{"Key": "sim2real", "Value": "obs-cloudfront-3"}]


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description} (last: {last!r})")


def _dist_status(cf, dist_id):
    r = cf.get_distribution(Id=dist_id)
    return r["Distribution"]["Status"], r["ETag"]


def _wait_deployed(cf, dist_id, timeout_s=1500.0) -> str:
    return _poll_until(lambda: _dist_status(cf, dist_id), lambda s: s[0] == "Deployed",
                       timeout_s=timeout_s, interval_s=15.0,
                       description=f"distribution {dist_id} to reach Deployed")[1]


def _code(exc) -> str:
    return ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code", "")


def _teardown_distributions(cf, dist_ids, timeout_s=1500.0) -> None:
    """Disable, wait for Deployed, delete — called from the check BODY on the success path.

    The engine bounds ctx cleanups at 60 s (simparity DEFAULT_CLEANUP_TIMEOUT_S) on a daemon thread
    it then abandons, far below one CloudFront disable->Deployed cycle. A blocking teardown
    registered with ctx.on_cleanup therefore never finishes AND strands every cleanup behind it.
    """
    for dist_id in dist_ids:
        resp = cf.get_distribution_config(Id=dist_id)
        cfg = resp["DistributionConfig"]
        if cfg["Enabled"]:
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
    for dist_id in dist_ids:
        cf.delete_distribution(Id=dist_id, IfMatch=_wait_deployed(cf, dist_id, timeout_s))


def _release_distribution(cf, dist_id) -> None:
    """Failure-path net, a few calls only: delete if already disabled and Deployed, else disable
    and report: a distribution is deletable only once it is disabled and Deployed."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchDistribution":
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc
        return
    try:
        cfg = resp["DistributionConfig"]
        if cfg["Enabled"]:
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
            raise RuntimeError(
                f"cloudfront distribution {dist_id}: disabled by cleanup, delete pending"
            )
        cur = cf.get_distribution(Id=dist_id)
        if cur["Distribution"]["Status"] != "Deployed":
            raise RuntimeError(
                f"cloudfront distribution {dist_id}: disabled, still deploying, delete pending"
            )
        cf.delete_distribution(Id=dist_id, IfMatch=cur["ETag"])
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchDistribution",):
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc


def _create_bucket(ctx, s3, bucket) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _create_capturing(ctx, cf, config):
    """CreateDistribution; on an unexpected success register teardown BEFORE returning.

    Returns ('ok', distribution) or ('error', (code, message, http_status)).
    """
    try:
        d = cf.create_distribution(DistributionConfig=config)["Distribution"]
    except Exception as exc:  # noqa: BLE001 — botocore ClientError carries .response
        resp = getattr(exc, "response", None)
        if not resp:
            raise
        return "error", (resp["Error"]["Code"], resp["Error"].get("Message", ""),
                         resp["ResponseMetadata"]["HTTPStatusCode"])
    ctx.on_cleanup(lambda: _release_distribution(cf, d["Id"]))
    return "ok", d


def _distributions_with_comment(cf, comment) -> list:
    out = []
    for page in cf.get_paginator("list_distributions").paginate():
        for item in page["DistributionList"].get("Items", []):
            if item.get("Comment") == comment:
                out.append(item["Id"])
    return out
# ===== end helpers =====


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Standard logging to a bucket with ACLs disabled is refused at CreateDistribution, creates no
    distribution, and the SAME config is accepted once the bucket's ownership allows ACLs.

    The two requests differ only in CallerReference; the verdict depends on the S3 bucket's state.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    log_bucket = ctx.unique_name("sim2real-obs3-acl-").lower()
    _create_bucket(ctx, s3, log_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, log_bucket))
    # Explicit, not the new-bucket default, so the check does not depend on an account setting.
    s3.put_bucket_ownership_controls(
        Bucket=log_bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]})
    logging_bucket = f"{log_bucket}.s3.amazonaws.com"
    comment = f"sim2real obs-cloudfront-3 {ctx.unique_name('acl-')}"

    def config() -> dict:
        return {
            "CallerReference": ctx.unique_name("sim2real-obs3-acl-"),
            "Comment": comment,
            "Enabled": False,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "origin", "DomainName": f"{log_bucket}.s3.{ctx.region}.amazonaws.com",
                "S3OriginConfig": {"OriginAccessIdentity": ""},
            }]},
            "DefaultCacheBehavior": {"TargetOriginId": "origin", "ViewerProtocolPolicy": "allow-all",
                                     "CachePolicyId": MANAGED_CACHING_OPTIMIZED},
            "Logging": {"Enabled": True, "IncludeCookies": False, "Bucket": logging_bucket,
                        "Prefix": "cf-acl/"},
        }

    # --- the break: the log bucket does not enable ACL access ------------------------------------
    outcome, value = _create_capturing(ctx, cf, config())
    assert outcome == "error", (
        f"CreateDistribution logging to an ACL-disabled bucket must be refused, but it created "
        f"{value.get('Id') if isinstance(value, dict) else value!r}")
    code, message, http_status = value
    assert (code, http_status) == ("InvalidArgument", 400), (
        f"expected InvalidArgument / 400, got {code!r} / {http_status!r}: {message!r}")
    assert message == f"The S3 bucket that you specified for CloudFront logs does not enable ACL access: {logging_bucket}", (
        f"the rejection must name the bucket and the ACL condition, got {message!r}")
    assert _distributions_with_comment(cf, comment) == [], (
        "a refused CreateDistribution must leave no distribution behind")

    # --- positive control: enable ACLs on the same bucket; the same config is accepted ----------
    s3.put_bucket_ownership_controls(
        Bucket=log_bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]})
    outcome, value = _create_capturing(ctx, cf, config())
    assert outcome == "ok", (
        f"with ObjectOwnership=BucketOwnerPreferred the identical config must be accepted, got {value!r}")
    dist = value
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAGS})
    stored = cf.get_distribution_config(Id=dist["Id"])["DistributionConfig"]["Logging"]
    assert stored == {"Enabled": True, "IncludeCookies": False, "Bucket": logging_bucket, "Prefix": "cf-acl/"}, (
        f"the accepted distribution must store the Logging block as sent, got {stored!r}")
    assert _distributions_with_comment(cf, comment) == [dist["Id"]], (
        "exactly the accepted distribution must exist under this run's unique comment")

    # --- teardown of the slow chain, in the body (see _teardown_distributions) -----------------
    _teardown_distributions(cf, [dist["Id"]])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
