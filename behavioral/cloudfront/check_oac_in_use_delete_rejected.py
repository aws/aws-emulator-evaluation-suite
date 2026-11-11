"""oac-in-use-delete-rejected."""
from __future__ import annotations

import time
import itertools
from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()

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

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource; one the check already deleted is skipped."""
    try:
        resp = get_fn(Id=resource_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchOriginAccessControl":
            return
        raise
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

def _wait_distribution_deployed(cf, dist_id, timeout_s=1200, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag."""
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

def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"

def _minimal_distribution_config(ctx, comment="", enabled=True, origin_domain=None, origin_id="primary-origin", extra_origins=None):
    """Build a minimal-but-valid DistributionConfig with a single custom origin."""
    domain = origin_domain or f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    origins = [{
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
    }]
    if extra_origins:
        origins.extend(extra_origins)
    return {
        "CallerReference": _caller_reference(ctx),
        "Comment": comment,
        "Enabled": enabled,
        "Origins": {"Quantity": len(origins), "Items": origins},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # Managed-CachingOptimized
        },
    }

_NO_SUCH_OAC = "The specified origin access control does not exist."

CHECK = "oac-in-use-delete-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteOriginAccessControl on an OAC a distribution origin references fails with
    OriginAccessControlInUse and leaves it and its ETag unchanged, and succeeds with the same IfMatch once
    the distribution is deleted; an unreferenced OAC deletes cleanly as the control."""
    cf = ctx.client("cloudfront")

    # ---- positive control: an unreferenced OAC deletes cleanly ----
    control_name = ctx.unique_name("sim2real-behav-oac-control-")
    control = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": control_name,
        "SigningProtocol": "sigv4",
        "SigningBehavior": "always",
        "OriginAccessControlOriginType": "s3",
    })
    control_id = control["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_origin_access_control, cf.delete_origin_access_control, control_id))
    control_got = cf.get_origin_access_control(Id=control_id)
    cf.delete_origin_access_control(Id=control_id, IfMatch=control_got["ETag"])
    control_gone_code, control_gone_message = _error(lambda: cf.get_origin_access_control(Id=control_id))
    assert control_gone_code == "NoSuchOriginAccessControl", (
        f"positive control: an unreferenced OAC should delete cleanly and read back gone, "
        f"got {control_gone_code}")
    assert control_gone_message == _NO_SUCH_OAC, (
        f"expected message {_NO_SUCH_OAC!r}, got {control_gone_message!r}")

    # ---- break: create the OAC under test and reference it from a live distribution origin ----
    name = ctx.unique_name("sim2real-behav-oac-inuse-")
    created = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": name,
        "SigningProtocol": "sigv4",
        "SigningBehavior": "always",
        "OriginAccessControlOriginType": "s3",
    })
    oac_id = created["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_origin_access_control, cf.delete_origin_access_control, oac_id))

    cfg = _minimal_distribution_config(ctx, comment="uses-oac")
    origin = cfg["Origins"]["Items"][0]
    del origin["CustomOriginConfig"]
    origin["DomainName"] = f"{ctx.unique_name('sim2real-behav-bucket-')}.s3.us-east-1.amazonaws.com"
    origin["S3OriginConfig"] = {"OriginAccessIdentity": ""}
    origin["OriginAccessControlId"] = oac_id

    resp = cf.create_distribution(DistributionConfig=cfg)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    got = cf.get_origin_access_control(Id=oac_id)
    etag = got["ETag"]
    code, message = _error(lambda: cf.delete_origin_access_control(Id=oac_id, IfMatch=etag))
    assert code == "OriginAccessControlInUse", (
        f"expected OriginAccessControlInUse deleting a referenced OAC, got {code}")
    expected = "The CloudFront origin access control is still being used."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # ---- effect absent: an independent read shows the OAC survived the refusal, untouched ----
    still_there = cf.get_origin_access_control(Id=oac_id)
    assert still_there["OriginAccessControl"]["Id"] == oac_id, (
        "the OAC should still exist after its blocked delete was refused")
    assert still_there["ETag"] == etag, (
        f"the OAC's ETag changed from {etag!r} to {still_there['ETag']!r} despite the refused delete"
    )

    # ---- restore: remove the distribution that references it ----
    _force_delete_distribution(cf, dist_id)

    # ---- the IDENTICAL delete call (same Id, same IfMatch) succeeds ----
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
    final_code, final_message = _error(lambda: cf.get_origin_access_control(Id=oac_id))
    assert final_code == "NoSuchOriginAccessControl", (
        f"expected the OAC to be gone once its distribution was deleted, got {final_code}")
    assert final_message == _NO_SUCH_OAC, (
        f"expected message {_NO_SUCH_OAC!r}, got {final_message!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
