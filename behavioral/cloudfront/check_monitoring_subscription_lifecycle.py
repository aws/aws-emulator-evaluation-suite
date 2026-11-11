"""monitoring-subscription-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "monitoring-subscription-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_distribution(cf, dist_id: str, timeout_s: float = 840.0, interval_s: float = 15.0) -> None:
    """Disable the distribution, wait for it to deploy, then delete it."""
    got = cf.get_distribution_config(Id=dist_id)
    cfg = dict(got["DistributionConfig"])
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=got["ETag"], DistributionConfig=cfg)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _delete_subscription_if_present(cf, dist_id: str) -> None:
    try:
        cf.delete_monitoring_subscription(DistributionId=dist_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "NoSuchMonitoringSubscription",
            "NoSuchDistribution",
        ):
            raise


def _disable_distribution_best_effort(cf, dist_id: str) -> None:
    """Teardown backstop that fits the cleanup budget: disable the distribution if the body did
    not get to delete it, so it can be deleted once it deploys."""
    try:
        got = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
            return
        raise
    cfg = dict(got["DistributionConfig"])
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=got["ETag"], DistributionConfig=cfg)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Monitoring subscription create->get->delete lifecycle tied to a real distribution,
    including that GetMonitoringSubscription 404s with NoSuchMonitoringSubscription both
    before any subscription is ever created and again after it has been deleted."""
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-monsub-origin-')}.s3.amazonaws.com"
    config = {
        "CallerReference": ctx.unique_name("sim2real-monsub-dist-cr-"),
        "Comment": "sim2real monitoring subscription test distribution",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "sim2real-origin",
                    "DomainName": origin_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "sim2real-origin",
            "ViewerProtocolPolicy": "allow-all",
            "TrustedSigners": {"Enabled": False, "Quantity": 0},
            "ForwardedValues": {"QueryString": False, "Cookies": {"Forward": "none"}},
            "MinTTL": 0,
        },
    }
    created = cf.create_distribution(DistributionConfig=config)
    dist_id = created["Distribution"]["Id"]
    cf.tag_resource(
        Resource=created["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real", "Value": "1"}]},
    )
    ctx.on_cleanup(lambda: _disable_distribution_best_effort(cf, dist_id))

    # Before any subscription has ever been created, CloudFront has no monitoring subscription
    # record for the distribution at all: GetMonitoringSubscription returns a 404
    # NoSuchMonitoringSubscription, not a "Disabled" status payload.
    no_such_message = "The monitoring subscription does not exist."
    baseline_code, baseline_message = _error(lambda: cf.get_monitoring_subscription(DistributionId=dist_id))
    assert baseline_code == "NoSuchMonitoringSubscription", (
        f"expected 404 NoSuchMonitoringSubscription before any subscription exists, "
        f"got {baseline_code!r}"
    )
    assert baseline_message == no_such_message, (
        f"expected message {no_such_message!r}, got {baseline_message!r}"
    )

    created_sub = cf.create_monitoring_subscription(
        DistributionId=dist_id,
        MonitoringSubscription={
            "RealtimeMetricsSubscriptionConfig": {"RealtimeMetricsSubscriptionStatus": "Enabled"}
        },
    )
    created_status = created_sub["MonitoringSubscription"]["RealtimeMetricsSubscriptionConfig"][
        "RealtimeMetricsSubscriptionStatus"
    ]
    assert created_status == "Enabled", f"expected Enabled on create, got {created_status!r}"
    ctx.on_cleanup(lambda: _delete_subscription_if_present(cf, dist_id))

    got = cf.get_monitoring_subscription(DistributionId=dist_id)
    got_status = got["MonitoringSubscription"]["RealtimeMetricsSubscriptionConfig"][
        "RealtimeMetricsSubscriptionStatus"
    ]
    assert got_status == "Enabled", f"expected Enabled on independent get, got {got_status!r}"

    # Re-creating over an existing subscription is a conflict, not silently accepted.
    code, message = _error(
        lambda: cf.create_monitoring_subscription(
            DistributionId=dist_id,
            MonitoringSubscription={
                "RealtimeMetricsSubscriptionConfig": {"RealtimeMetricsSubscriptionStatus": "Enabled"}
            },
        )
    )
    assert code == "MonitoringSubscriptionAlreadyExists", f"expected 409 conflict, got {code!r}"
    expected = "A monitoring subscription already exists for this distribution"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    cf.delete_monitoring_subscription(DistributionId=dist_id)

    # Once the subscription is deleted, CloudFront drops the monitoring-subscription record
    # entirely rather than retaining a "Disabled" record: GetMonitoringSubscription goes back
    # to the same 404 NoSuchMonitoringSubscription seen before any subscription ever existed.
    after_delete_code, after_delete_message = _error(
        lambda: cf.get_monitoring_subscription(DistributionId=dist_id)
    )
    assert after_delete_code == "NoSuchMonitoringSubscription", (
        f"expected 404 NoSuchMonitoringSubscription after deletion, got {after_delete_code!r}"
    )
    assert after_delete_message == no_such_message, (
        f"expected message {no_such_message!r}, got {after_delete_message!r}"
    )

    # The earlier MonitoringSubscriptionAlreadyExists conflict is about existing state, not a
    # permanent block: once the prior subscription is gone, the identical create call succeeds
    # again. The body deletes this second subscription before it deletes the distribution.
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
        f"expected create to succeed again after prior delete, got {recreated_status!r}"
    )

    # Terminal read: independent of the create call above, at the same destination.
    final_got = cf.get_monitoring_subscription(DistributionId=dist_id)
    final_status = final_got["MonitoringSubscription"]["RealtimeMetricsSubscriptionConfig"][
        "RealtimeMetricsSubscriptionStatus"
    ]
    assert final_status == "Enabled", (
        f"expected independent get to reflect Enabled after recreate, got {final_status!r}"
    )

    # Tear down inside the check budget: disable, wait for Deployed and delete take longer than
    # the cleanup budget, so the registered cleanups are only the backstop.
    _delete_subscription_if_present(cf, dist_id)
    _delete_distribution(cf, dist_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
