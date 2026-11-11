"""cloudwatch-destination-never-resolves-a-dimension-it-did-not-declare."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cloudwatch-destination-never-resolves-a-dimension-it-did-not-declare"
GROUP = "metrics-delivery"
SERVICES = ["cloudwatch", "ses"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_NAMESPACE = "AWS/SES"
_METRIC_POLL_TIMEOUT_S = 300.0
_METRIC_POLL_INTERVAL_S = 2.0
#: The absence hold, a fixed window read after the declared dimension's datapoint has landed.
_ABSENCE_HOLD_S = 10.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _sending_domain(ctx, route53, sesv2):
    """The account's tagged, SES-verified public hosted zone domain; an account without one fails the check."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified for sending in "
                    f"{ctx.region} (DKIM {identity['DkimAttributes']['Status']!r}); it must be "
                    "verified before this check runs"
                )
                return domain
    raise AssertionError(
        "this account has no DNS baseline zone (a public hosted zone carrying the baseline "
        "tag, verified in SES) and so no sending domain; the check requires one"
    )


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _metric_sum(cw, metric_name, dimensions, start, end):
    got = cw.get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=end,
        Period=60,
        Statistics=["Sum"],
    )
    points = got.get("Datapoints", [])
    if not points:
        return None
    return sum(p["Sum"] for p in points)


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """A destination declaring only a custom message tag publishes `Send` under that tag alone.

    ses:configuration-set is never added by default; the declared datapoint proves delivery.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    cw = ctx.client("cloudwatch")
    domain = _sending_domain(ctx, route53, sesv2)
    sender = f"{ctx.unique_name('sim2real-')}@{domain}"

    config_set = ctx.unique_name("sim2real-behav-cwabs-")
    campaign_value = ctx.unique_name("sim2real-behav-campaign-")

    sesv2.create_configuration_set(ConfigurationSetName=config_set)
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))

    # Deliberately declares ONLY the custom message-tag dimension — never
    # "ses:configuration-set" — so any appearance of the latter on this send's datapoint would
    # have to come from the destination defaulting it in, not from this check's own request.
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName="sim2real-cw-abs",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND"],
            "CloudWatchDestination": {
                "DimensionConfigurations": [
                    {
                        "DimensionName": "campaign",
                        "DimensionValueSource": "MESSAGE_TAG",
                        "DefaultDimensionValue": "none",
                    },
                ]
            },
        },
    )

    start = time.time()
    message_id = sesv2.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
        Content={
            "Simple": {
                "Subject": {"Data": f"sim2real {CHECK}"},
                "Body": {"Text": {"Data": "cw-undeclared-dim probe"}},
            }
        },
        ConfigurationSetName=config_set,
        EmailTags=[{"Name": "campaign", "Value": campaign_value}],
    )["MessageId"]
    assert message_id, "SendEmail must return a MessageId for an accepted message"

    def _window_end():
        return time.time() + 60

    declared_dims = [{"Name": "campaign", "Value": campaign_value}]
    declared_total = _poll_until(
        ctx,
        lambda: _metric_sum(cw, "Send", declared_dims, start - 60, _window_end()),
        lambda v: v is not None,
        timeout_s=_budget_s(ctx, _METRIC_POLL_TIMEOUT_S),
        interval_s=_METRIC_POLL_INTERVAL_S,
        description=f"AWS/SES Send metric resolved for the DECLARED dimension campaign={campaign_value!r}",
    )
    assert declared_total == 1, (
        f"positive control: expected exactly 1 Send datapoint under the declared campaign "
        f"dimension, got {declared_total!r}"
    )

    # The declared dimension's datapoint comes from the same sends, so the absence is read across
    # a fixed hold after it landed, every sample asserted.
    undeclared_dims = [
        {"Name": "campaign", "Value": campaign_value},
        {"Name": "ses:configuration-set", "Value": config_set},
    ]
    hold_deadline = time.monotonic() + _ABSENCE_HOLD_S
    while True:
        undeclared_total = _metric_sum(cw, "Send", undeclared_dims, start - 60, _window_end())
        assert undeclared_total is None, (
            f"a CloudWatch destination that never declared the ses:configuration-set dimension "
            f"must not publish a datapoint under it; got {undeclared_total!r}"
        )
        if time.monotonic() >= hold_deadline:
            break
        time.sleep(_METRIC_POLL_INTERVAL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
