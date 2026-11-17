"""distribution-origin-access-control-type-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distribution-origin-access-control-type-mismatch-rejected"
GROUP = "origin-access-control"
SERVICES = ["cloudfront", "s3"]

#: AWS's managed "CachingOptimized" cache policy id (CDK's CachePolicy.CACHING_OPTIMIZED pins it).
_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

#: The refusal CreateDistribution returns when an origin's OriginAccessControlId was created for a
#: different origin kind than the origin it is attached to.
_TYPE_MISMATCH = (
    "IllegalOriginAccessConfiguration",
    "Illegal configuration: The origin type and OAC origin type differ",
)


def _error(fn):
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cf.get_distribution(Id=dist_id)["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s")


def _delete_distribution(cf, dist_id) -> None:
    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """CreateDistribution refuses an origin whose OriginAccessControlId was created for a
    different origin kind than the origin carrying it, and the refused call never consumes its
    CallerReference: reusing it with the matching origin kind creates a distribution normally.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfoac-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: ctx.client("s3").delete_bucket(Bucket=bucket))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfoac-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    caller_reference = ctx.unique_name("sim2real-behav-cfoac-cr-")
    bucket_domain = f"{bucket}.s3.{ctx.region}.amazonaws.com"

    def create_with_custom_origin():
        return cf.create_distribution(DistributionConfig={
            "CallerReference": caller_reference,
            "Comment": "sim2real oac type mismatch",
            "Enabled": False,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "mismatched-origin",
                "DomainName": bucket_domain,
                "CustomOriginConfig": {
                    "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only",
                    "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                },
                "OriginAccessControlId": oac_id,
            }]},
            "DefaultCacheBehavior": {
                "TargetOriginId": "mismatched-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _CACHING_OPTIMIZED,
            },
        })

    error = _error(create_with_custom_origin)
    assert error == _TYPE_MISMATCH, (
        f"an s3-type OAC attached to a custom-origin config must be refused with "
        f"{_TYPE_MISMATCH!r}, got {error!r}"
    )

    # The refused call must not have consumed the CallerReference: reusing it with the matching
    # origin kind (S3OriginConfig, as the OAC's type requires) must create a NEW distribution
    # rather than fail with a conflicting-config error over an already-used reference.
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": caller_reference,
        "Comment": "sim2real oac type mismatch control",
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "matched-origin",
            "DomainName": bucket_domain,
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "matched-origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _CACHING_OPTIMIZED,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx.client("cloudfront"), dist_id))

    config = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    origin = config["Origins"]["Items"][0]
    assert config["CallerReference"] == caller_reference, (
        f"the accepted distribution's CallerReference is {config['CallerReference']!r}, expected "
        f"the reused value {caller_reference!r}"
    )
    assert "S3OriginConfig" in origin and "CustomOriginConfig" not in origin, (
        f"the accepted distribution's origin is {sorted(origin)!r}, expected the S3OriginConfig "
        f"variant that matches the OAC's declared origin type"
    )
    assert origin["OriginAccessControlId"] == oac_id, (
        f"the accepted distribution kept OriginAccessControlId {origin['OriginAccessControlId']!r}, "
        f"expected {oac_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
