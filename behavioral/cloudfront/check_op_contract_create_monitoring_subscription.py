"""op-contract-createMonitoringSubscription."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createMonitoringSubscription"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMonitoringSubscription enables additional metrics for a distribution; re-enabling an
    existing subscription is rejected without disturbing it, and once the subscription is removed
    the identical create call that was just rejected succeeds again."""
    cf = ctx.client("cloudfront")
    dist_id = _create_minimal_distribution(ctx)

    resp = cf.create_monitoring_subscription(
        DistributionId=dist_id,
        MonitoringSubscription={
            "RealtimeMetricsSubscriptionConfig": {"RealtimeMetricsSubscriptionStatus": "Enabled"}
        },
    )
    status = resp["MonitoringSubscription"]["RealtimeMetricsSubscriptionConfig"][
        "RealtimeMetricsSubscriptionStatus"
    ]
    assert status == "Enabled", f"expected Enabled on create response, got {status!r}"

    # The subscription is independently retrievable and reflects the same status.
    fetched = _get_status(cf, dist_id)
    assert fetched == "Enabled", f"expected Enabled on independent read, got {fetched!r}"

    # Distinct error boundary: enabling an already-enabled subscription for the same distribution
    # is refused, and the refusal leaves the existing subscription untouched.
    code, message = _error(
        lambda: cf.create_monitoring_subscription(
            DistributionId=dist_id,
            MonitoringSubscription={
                "RealtimeMetricsSubscriptionConfig": {"RealtimeMetricsSubscriptionStatus": "Enabled"}
            },
        )
    )
    assert code == "MonitoringSubscriptionAlreadyExists", f"expected MonitoringSubscriptionAlreadyExists, got {code}"
    expected = "A monitoring subscription already exists for this distribution"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = _get_status(cf, dist_id)
    assert unchanged == "Enabled", (
        f"expected the rejected re-create to leave the subscription Enabled, got {unchanged!r}"
    )

    # Restore: remove the subscription, then re-issue the identical create call that was just
    # rejected -- proving the rejection was about the conflicting state, not the request shape.
    cf.delete_monitoring_subscription(DistributionId=dist_id)
    gone_code, gone_message = _error(lambda: cf.get_monitoring_subscription(DistributionId=dist_id))
    assert gone_code == "NoSuchMonitoringSubscription", (
        f"expected NoSuchMonitoringSubscription after delete, got {gone_code}"
    )
    expected = "The monitoring subscription does not exist."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    restored = cf.create_monitoring_subscription(
        DistributionId=dist_id,
        MonitoringSubscription={
            "RealtimeMetricsSubscriptionConfig": {"RealtimeMetricsSubscriptionStatus": "Enabled"}
        },
    )
    restored_status = restored["MonitoringSubscription"]["RealtimeMetricsSubscriptionConfig"][
        "RealtimeMetricsSubscriptionStatus"
    ]
    assert restored_status == "Enabled", (
        f"expected the identical create to succeed after restore, got {restored_status!r}"
    )

    # Terminal assertion: an independent read at the destination, not the mutating call's own response.
    terminal = _get_status(cf, dist_id)
    assert terminal == "Enabled", f"expected Enabled on terminal independent read, got {terminal!r}"


def _create_minimal_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-dist-")
    origin_domain = f"{ctx.unique_name('origin')}.example.com"
    config = {
        "CallerReference": ref,
        "Comment": "sim2real behavioral check",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "http-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _cleanup_distribution(ctx, dist_id))
    return dist_id


def _cleanup_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        try:
            cf.delete_monitoring_subscription(DistributionId=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "NoSuchDistribution",
                "NoSuchMonitoringSubscription",
            ):
                raise
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        etag = cfg_resp["ETag"]
        dist_config = cfg_resp["DistributionConfig"]
        if dist_config.get("Enabled"):
            dist_config["Enabled"] = False
            etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=dist_config)["ETag"]
        deadline = time.monotonic() + 180
        status = None
        while time.monotonic() < deadline:
            info = cf.get_distribution(Id=dist_id)
            status = info["Distribution"]["Status"]
            etag = info["ETag"]
            if status == "Deployed":
                break
            time.sleep(10)
        if status == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchMonitoringSubscription",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
            raise


def _get_status(cf, dist_id: str) -> str:
    resp = cf.get_monitoring_subscription(DistributionId=dist_id)
    return resp["MonitoringSubscription"]["RealtimeMetricsSubscriptionConfig"][
        "RealtimeMetricsSubscriptionStatus"
    ]


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
