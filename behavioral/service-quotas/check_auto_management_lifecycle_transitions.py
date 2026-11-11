"""auto-management-lifecycle-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "auto-management-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["service-quotas"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_topic(ctx, suffix):
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name(f"sim2real-sq-automgmt-{suffix}-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control", "resource:account-singleton:service-quotas-auto-management")
def run(ctx) -> None:
    """StartAutoManagement reaches ENABLED with OptInType NotifyOnly and the first topic,
    UpdateAutoManagement switches to the second topic and excludes a real lambda quota while staying
    ENABLED, and StopAutoManagement reaches DISABLED."""
    sq = ctx.client("service-quotas")
    ctx.on_cleanup(lambda: _swallow(lambda: sq.stop_auto_management()))

    topic_a = _create_topic(ctx, "a")
    topic_b = _create_topic(ctx, "b")

    lambda_quotas = sq.list_service_quotas(ServiceCode="lambda")["Quotas"]
    adjustable_lambda = next((q for q in lambda_quotas if q["Adjustable"]), None)
    assert adjustable_lambda is not None, "expected at least one adjustable lambda quota"

    sq.start_auto_management(OptInLevel="ACCOUNT", OptInType="NotifyOnly", NotificationArn=topic_a)

    enabled = _poll_until(
        lambda: sq.get_auto_management_configuration(),
        lambda cfg: cfg.get("OptInStatus") == "ENABLED",
    )
    assert enabled["OptInType"] == "NotifyOnly", f"expected OptInType=NotifyOnly, got {enabled.get('OptInType')!r}"
    assert enabled["NotificationArn"] == topic_a, (
        f"expected NotificationArn={topic_a!r}, got {enabled.get('NotificationArn')!r}"
    )

    sq.update_auto_management(
        NotificationArn=topic_b,
        ExclusionList={"lambda": [adjustable_lambda["QuotaCode"]]},
    )
    updated = _poll_until(
        lambda: sq.get_auto_management_configuration(),
        lambda cfg: cfg.get("NotificationArn") == topic_b,
    )
    assert updated["OptInStatus"] == "ENABLED", (
        f"expected OptInStatus=ENABLED after update, got {updated.get('OptInStatus')!r}"
    )
    excluded_codes = {info["QuotaCode"] for info in updated.get("ExclusionList", {}).get("lambda", [])}
    assert adjustable_lambda["QuotaCode"] in excluded_codes, (
        f"expected {adjustable_lambda['QuotaCode']!r} in lambda ExclusionList, got {excluded_codes!r}"
    )

    sq.stop_auto_management()
    _poll_until(
        lambda: sq.get_auto_management_configuration(),
        lambda cfg: cfg.get("OptInStatus") == "DISABLED",
    )


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResourceException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
