"""op-contract-deleteMonitoringSubscription."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteMonitoringSubscription"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMonitoringSubscription: deleting an already-deleted subscription is
    rejected distinctly, and a correct delete removes it so Get reports NotFound."""
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-mon-origin')}.example.com"

    dist = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-mon-dist-"),
            "Comment": "sim2real behavioral check",
            "Enabled": False,
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
        }
    )
    dist_id = dist["Distribution"]["Id"]
    dist_arn = dist["Distribution"]["ARN"]
    ctx.on_cleanup(lambda dist_id=dist_id: _cleanup_distribution(ctx, dist_id))
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "sim2real", "Value": "true"}]})

    cf.create_monitoring_subscription(
        DistributionId=dist_id,
        MonitoringSubscription={
            "RealtimeMetricsSubscriptionConfig": {"RealtimeMetricsSubscriptionStatus": "Enabled"}
        },
    )

    # success path
    cf.delete_monitoring_subscription(DistributionId=dist_id)
    gone_code, gone_message = _error(lambda: cf.get_monitoring_subscription(DistributionId=dist_id))
    assert gone_code == "NoSuchMonitoringSubscription", (
        f"expected NoSuchMonitoringSubscription, got {gone_code}"
    )
    assert gone_message == "The monitoring subscription does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )

    # error boundary: deleting an already-deleted subscription
    repeat_code, repeat_message = _error(lambda: cf.delete_monitoring_subscription(DistributionId=dist_id))
    assert repeat_code == "NoSuchMonitoringSubscription", (
        f"expected NoSuchMonitoringSubscription on repeat delete, got {repeat_code}"
    )
    assert repeat_message == "The monitoring subscription does not exist.", (
        f"expected the exact refusal message, got {repeat_message!r}"
    )

    # restore + identical call succeeds: the deleted identifier is reusable, proving the
    # earlier delete actually cleared server-side state rather than just flipping a flag
    # that GetMonitoringSubscription happens to also read as "not found".
    recreated = cf.create_monitoring_subscription(
        DistributionId=dist_id,
        MonitoringSubscription={
            "RealtimeMetricsSubscriptionConfig": {"RealtimeMetricsSubscriptionStatus": "Enabled"}
        },
    )
    recreated_status = recreated["MonitoringSubscription"]["RealtimeMetricsSubscriptionConfig"][
        "RealtimeMetricsSubscriptionStatus"
    ]
    assert recreated_status == "Enabled", (
        f"expected recreated subscription to be Enabled, got {recreated_status}"
    )
    cf.delete_monitoring_subscription(DistributionId=dist_id)
    final_code, final_message = _error(lambda: cf.get_monitoring_subscription(DistributionId=dist_id))
    assert final_code == "NoSuchMonitoringSubscription", (
        f"expected NoSuchMonitoringSubscription after re-delete, got {final_code}"
    )
    assert final_message == "The monitoring subscription does not exist.", (
        f"expected the exact refusal message, got {final_message!r}"
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
