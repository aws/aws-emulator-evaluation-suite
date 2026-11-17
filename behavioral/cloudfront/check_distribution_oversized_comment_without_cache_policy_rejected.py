"""distribution-oversized-comment-without-cache-policy-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distribution-oversized-comment-without-cache-policy-rejected"
GROUP = "distribution-validation"
SERVICES = ["cloudfront"]

# Managed-CachingOptimized — a stable AWS-managed cache policy id (reference data).
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_COMMENT_TOO_BIG = ("InvalidArgument", "The parameter Comment is too big.")


def _error(fn):
    """(Error.Code, Error.Message, HTTPStatusCode) of the ClientError fn() raises; an
    unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), err.get("Message"), status
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, timeout_s=1800, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag.

    CloudFront is a globally scoped service and a distribution deployment
    routinely takes several minutes, so the deadline is deliberately long.
    """
    holder = {"etag": etag_hint}

    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(
        probe,
        lambda status: status == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"distribution {dist_id} Status=Deployed",
    )
    return holder["etag"]


def _force_delete_distribution(cf, dist_id):
    """Teardown: disable if needed, wait for Deployed, delete with the current ETag."""
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _custom_origin(origin_id, domain):
    return {
        "Id": origin_id,
        "DomainName": domain,
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }


def _config(ctx, caller_reference, comment, behavior, origin_id="primary-origin"):
    domain = f"{ctx.unique_name('sim2real-behav-cflen-origin-')}.example.com"
    return {
        "CallerReference": caller_reference,
        "Comment": comment,
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [_custom_origin(origin_id, domain)]},
        "DefaultCacheBehavior": behavior,
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDistribution with a 129-character Comment and a default cache behavior that has
    neither CachePolicyId nor ForwardedValues is refused with the Comment-too-big InvalidArgument
    and creates nothing; a 128-character Comment with a CachePolicyId is accepted.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/APIReference/API_DistributionConfig.html
    """
    cf = ctx.client("cloudfront")

    marker = ctx.unique_name("sim2real-behav-cflen-")
    comment_129 = (marker + "x" * 200)[:129]
    assert len(comment_129) == 129, len(comment_129)
    comment_128 = comment_129[:128]
    assert len(comment_128) == 128, len(comment_128)

    # 1. Negative: a DefaultCacheBehavior with neither CachePolicyId nor ForwardedValues,
    #    and a 129-character Comment.
    bare_behavior = {
        "TargetOriginId": "primary-origin",
        "ViewerProtocolPolicy": "redirect-to-https",
    }
    rejected_cfg = _config(
        ctx, ctx.unique_name("sim2real-behav-cflen-ref-"), comment_129, bare_behavior
    )
    code, message, status = _error(lambda: cf.create_distribution(DistributionConfig=rejected_cfg))
    assert (code, message) == _COMMENT_TOO_BIG, (
        f"expected {_COMMENT_TOO_BIG!r}, got ({code!r}, {message!r})"
    )
    assert status == 400, f"expected HTTP status 400, got {status!r}"

    # Effect absent: the rejected create must not have minted a distribution. CallerReference
    # is not exposed by ListDistributions, so match on this check's unique Comment prefix.
    leaked = []
    for page in cf.get_paginator("list_distributions").paginate():
        for summary in page["DistributionList"].get("Items", []) or []:
            if summary.get("Comment", "").startswith(marker):
                leaked.append(summary["Id"])
    assert not leaked, f"a rejected CreateDistribution must not leave a distribution behind, found {leaked}"

    # 2. Positive control: the same shape, 128-character Comment and a CachePolicyId.
    accepted_behavior = {
        "TargetOriginId": "primary-origin",
        "ViewerProtocolPolicy": "redirect-to-https",
        "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
    }
    accepted_cfg = _config(
        ctx, ctx.unique_name("sim2real-behav-cflen-ref-"), comment_128, accepted_behavior
    )
    created = cf.create_distribution(DistributionConfig=accepted_cfg)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    assert created["ResponseMetadata"]["HTTPStatusCode"] == 201, (
        created["ResponseMetadata"]["HTTPStatusCode"]
    )

    readback = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert readback["Comment"] == comment_128, f"expected Comment {comment_128!r}, got {readback['Comment']!r}"
    assert readback["DefaultCacheBehavior"]["CachePolicyId"] == MANAGED_CACHING_OPTIMIZED, (
        readback["DefaultCacheBehavior"].get("CachePolicyId")
    )
    assert "ForwardedValues" not in readback["DefaultCacheBehavior"], (
        f"unexpected ForwardedValues: {readback['DefaultCacheBehavior'].get('ForwardedValues')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
