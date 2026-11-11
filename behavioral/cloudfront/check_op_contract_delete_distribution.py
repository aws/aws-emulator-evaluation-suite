"""op-contract-deleteDistribution."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteDistribution"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


_MANAGED_CACHING_DISABLED_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDistribution: an enabled distribution is rejected with
    DistributionNotDisabled; once disabled and fully deployed, delete succeeds and
    a subsequent Get reports NoSuchDistribution."""
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-origin')}.example.com"

    created = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": ctx.unique_name("sim2real-dist-"),
                "Comment": "sim2real behavioral check",
                "Enabled": True,
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "primary-origin",
                            "DomainName": origin_domain,
                            "CustomOriginConfig": {
                                "HTTPPort": 80,
                                "HTTPSPort": 443,
                                "OriginProtocolPolicy": "https-only",
                                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                            },
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "primary-origin",
                    "ViewerProtocolPolicy": "allow-all",
                    "CachePolicyId": _MANAGED_CACHING_DISABLED_ID,
                },
            },
            "Tags": {"Items": [{"Key": "sim2real", "Value": "op-contract-deleteDistribution"}]},
        }
    )
    dist_id = created["Distribution"]["Id"]
    etag = created["ETag"]

    ctx.on_cleanup(lambda dist_id=dist_id: _cleanup_distribution(ctx, dist_id))

    # error boundary: an enabled distribution can't be deleted
    conflict_code, conflict_message = _error(lambda: cf.delete_distribution(Id=dist_id, IfMatch=etag))
    assert conflict_code == "DistributionNotDisabled", (
        f"expected DistributionNotDisabled, got {conflict_code}"
    )
    assert conflict_message == "The distribution you are trying to delete has not been disabled.", (
        f"expected the exact refusal message, got {conflict_message!r}"
    )

    # effect-absent: the rejected delete must not have touched the distribution
    still_there = cf.get_distribution(Id=dist_id)["Distribution"]
    assert still_there["DistributionConfig"]["Enabled"] is True, (
        f"rejected delete must leave the distribution enabled, got Enabled="
        f"{still_there['DistributionConfig']['Enabled']}"
    )

    # disable it, then wait for the disable to fully deploy before delete is legal
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    cfg["Enabled"] = False
    updated = cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    updated_enabled = updated["Distribution"]["DistributionConfig"]["Enabled"]
    assert updated_enabled is False, f"expected the disable update to set Enabled=False, got {updated_enabled!r}"

    deployed_etag = _wait_distribution_deployed(ctx, dist_id, timeout_s=900.0)
    if deployed_etag is None:
        raise AssertionError(
            "unreachable: distribution did not reach Deployed status within 900s",
        )

    # success path
    cf.delete_distribution(Id=dist_id, IfMatch=deployed_etag)
    gone_code, gone_message = _error(lambda: cf.get_distribution(Id=dist_id))
    assert gone_code == "NoSuchDistribution", f"expected NoSuchDistribution, got {gone_code}"
    assert gone_message == "The specified distribution does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )

    # a mutation on the now-dead id also fails, and does not resurrect it
    redelete_code, redelete_message = _error(lambda: cf.delete_distribution(Id=dist_id, IfMatch=deployed_etag))
    assert redelete_code == "NoSuchDistribution", (
        f"expected a second delete of a gone distribution to fail NoSuchDistribution, got {redelete_code}"
    )
    assert redelete_message == "The specified distribution does not exist.", (
        f"expected the exact refusal message, got {redelete_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_distribution_deployed(ctx, dist_id, timeout_s=900.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp["ETag"]
        time.sleep(interval_s)
    return None


def _cleanup_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        cfg = cfg_resp["DistributionConfig"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
        etag = _wait_distribution_deployed(ctx, dist_id, timeout_s=900.0)
        if etag is None:
            etag = cf.get_distribution(Id=dist_id)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
