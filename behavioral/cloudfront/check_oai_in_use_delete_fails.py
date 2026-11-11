"""oai-in-use-delete-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"

def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")

def _wait_distribution_deployed(cf, dist_id, timeout_s=1200, interval_s=15, etag_hint=None):
    holder = {"etag": etag_hint}
    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]
    _poll_until(probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s)
    return holder["etag"]

def _force_delete_distribution(cf, dist_id):
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
            return
        raise
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

def _force_delete_oai(cf, oai_id):
    try:
        resp = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchCloudFrontOriginAccessIdentity":
            return
        raise
    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=resp["ETag"])

def _minimal_distribution_config(name, **overrides):
    origin_domain = f"{name}.s3.amazonaws.com"
    config = {
        "CallerReference": name,
        "Comment": name,
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID,
        },
    }
    config.update(overrides)
    return config

CHECK = "oai-in-use-delete-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an OAI still referenced by a distribution's S3 origin MUST fail
    (CloudFrontOriginAccessIdentityInUse), must not remove the OAI, and once the
    reference is torn down the identical delete call succeeds and the OAI is gone."""
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-behav-oai-inuse-")
    oai_resp = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={"CallerReference": ref, "Comment": "in-use test"}
    )
    oai_id = oai_resp["CloudFrontOriginAccessIdentity"]["Id"]
    oai_etag = oai_resp["ETag"]
    ctx.on_cleanup(lambda: _force_delete_oai(cf, oai_id))

    dist_name = ctx.unique_name("sim2real-behav-dist-oai-")
    dist_cfg = _minimal_distribution_config(dist_name)
    dist_cfg["Origins"]["Items"][0]["S3OriginConfig"]["OriginAccessIdentity"] = (
        f"origin-access-identity/cloudfront/{oai_id}"
    )
    create_resp = cf.create_distribution(DistributionConfig=dist_cfg)
    dist_id = create_resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    _wait_distribution_deployed(cf, dist_id)

    # break: the OAI is now referenced by a deployed distribution's S3 origin.
    code, message = _error(
        lambda: cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=oai_etag)
    )
    assert code == "CloudFrontOriginAccessIdentityInUse", (
        f"expected CloudFrontOriginAccessIdentityInUse, got {code}"
    )
    expected = "The CloudFront origin access identity is still being used."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the rejected delete must not have removed the OAI.
    still_there = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    assert still_there["CloudFrontOriginAccessIdentity"]["Id"] == oai_id, (
        f"the rejected delete must not have removed the OAI: expected {oai_id!r} to still be "
        f"gettable, got {still_there!r}"
    )

    # restore + positive control: once the distribution no longer references the
    # OAI, the identical delete call succeeds (proving the earlier rejection was
    # specific to being in-use, not a blanket refusal of every delete).
    _force_delete_distribution(cf, dist_id)
    fresh = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=fresh["ETag"])

    final_code, final_message = _error(lambda: cf.get_cloud_front_origin_access_identity(Id=oai_id))
    assert final_code == "NoSuchCloudFrontOriginAccessIdentity", (
        f"expected NoSuchCloudFrontOriginAccessIdentity after the OAI was actually deleted, "
        f"got {final_code}"
    )
    expected = "The specified CloudFront origin access identity does not exist."
    assert final_message == expected, f"expected message {expected!r}, got {final_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
