"""distribution-delete-while-enabled-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "distribution-delete-while-enabled-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDistribution rejects an enabled distribution; disabling it first lets the same delete
    succeed, and the deleted id is then gone and unusable."""
    cf = ctx.client("cloudfront")

    dist_id, _ = _create_distribution(ctx, cf, enabled=True)
    ctx.on_cleanup(lambda: _cleanup_distribution(cf, dist_id))

    etag = cf.get_distribution(Id=dist_id)["ETag"]
    code, message = _error(lambda: cf.delete_distribution(Id=dist_id, IfMatch=etag))
    assert code == "DistributionNotDisabled", f"expected DistributionNotDisabled, got {code!r}"
    assert message == "The distribution you are trying to delete has not been disabled.", (
        f"unexpected DistributionNotDisabled message: {message!r}"
    )

    # effect absent: the distribution still exists, and still enabled, after the rejected delete
    still_there = cf.get_distribution(Id=dist_id)["Distribution"]
    still_enabled = still_there["DistributionConfig"]["Enabled"]
    assert still_enabled is True, f"expected distribution {dist_id} to remain Enabled=True, got {still_enabled!r}"

    # restore: disable, wait for the disable to deploy, then the same delete succeeds
    current = cf.get_distribution_config(Id=dist_id)
    cfg = current["DistributionConfig"]
    cfg["Enabled"] = False
    updated = cf.update_distribution(Id=dist_id, IfMatch=current["ETag"], DistributionConfig=cfg)
    updated_enabled = updated["Distribution"]["DistributionConfig"]["Enabled"]
    assert updated_enabled is False, f"expected update to set Enabled=False, got {updated_enabled!r}"

    _wait_distribution_deployed(cf, dist_id)
    final_etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=final_etag)

    code2, message2 = _error(lambda: cf.get_distribution(Id=dist_id))
    assert code2 == "NoSuchDistribution", f"expected NoSuchDistribution after delete, got {code2!r}"
    assert message2 == "The specified distribution does not exist.", f"unexpected NoSuchDistribution message: {message2!r}"

    # gone AND unusable: a second delete on the same dead id fails the same way, not e.g. a 500
    code3, message3 = _error(lambda: cf.delete_distribution(Id=dist_id, IfMatch=final_etag))
    assert code3 == "NoSuchDistribution", f"expected NoSuchDistribution on double-delete, got {code3!r}"
    assert message3 == "The specified distribution does not exist.", f"unexpected NoSuchDistribution message: {message3!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_distribution(ctx, cf, *, enabled):
    bucket_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.amazonaws.com"
    cfg = {
        "CallerReference": ctx.unique_name("sim2real-cf-"),
        "Comment": "sim2real behavioral check",
        "Enabled": enabled,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": bucket_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_DISABLED,
        },
    }
    resp = cf.create_distribution(DistributionConfig=cfg)
    dist = resp["Distribution"]
    return dist["Id"], dist["ARN"]


def _wait_distribution_deployed(cf, dist_id, timeout_s=1500, interval_s=20):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s (last={status})")


def _cleanup_distribution(cf, dist_id):
    from botocore.exceptions import ClientError

    try:
        current = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = current["DistributionConfig"]
    etag = current["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        updated = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
        etag = updated["ETag"]
    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
