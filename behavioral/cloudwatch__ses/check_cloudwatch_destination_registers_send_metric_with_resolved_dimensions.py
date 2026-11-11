"""cloudwatch-destination-registers-send-metric-with-resolved-dimensions."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cloudwatch-destination-registers-send-metric-with-resolved-dimensions"
GROUP = "metrics-delivery"
SERVICES = ["cloudwatch", "ses"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_NAMESPACE = "AWS/SES"
_METRIC_POLL_TIMEOUT_S = 300.0
_METRIC_POLL_INTERVAL_S = 15.0


def _sending_domain(ctx, route53, sesv2):
    """The account's DNS baseline domain, the apex of its public hosted zone tagged
    _BASELINE_TAG, which SES has verified."""
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
                    f"{ctx.region} (DKIM {identity['DkimAttributes']['Status']!r})"
                )
                return domain
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has "
        "no verified domain to send from"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
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


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/ses/latest/dg/event-publishing-retrieving-cloudwatch.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
    "timing:real-time",
)
def run(ctx) -> None:
    """A CloudWatch event destination resolves a message tag, a MIME header and the configuration
    set into their declared dimensions on one `Send` datapoint after a real send.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    cw = ctx.client("cloudwatch")
    domain = _sending_domain(ctx, route53, sesv2)
    sender = f"{ctx.unique_name('sim2real-')}@{domain}"

    config_set = ctx.unique_name("sim2real-behav-cwdim-")
    campaign_value = ctx.unique_name("sim2real-behav-campaign-")
    header_value = ctx.unique_name("sim2real-behav-hdrval-")

    sesv2.create_configuration_set(ConfigurationSetName=config_set)
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))

    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName="sim2real-cw",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND"],
            "CloudWatchDestination": {
                # SES resolves ses:configuration-set into a dimension only when it is declared
                # here; declaring only the custom dimensions publishes them alone.
                "DimensionConfigurations": [
                    {
                        "DimensionName": "ses:configuration-set",
                        "DimensionValueSource": "MESSAGE_TAG",
                        "DefaultDimensionValue": "none",
                    },
                    {
                        "DimensionName": "campaign",
                        "DimensionValueSource": "MESSAGE_TAG",
                        "DefaultDimensionValue": "none",
                    },
                    {
                        "DimensionName": "X-Custom-Header",
                        "DimensionValueSource": "EMAIL_HEADER",
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
                "Body": {"Text": {"Data": "cw-evt probe"}},
                "Headers": [{"Name": "X-Custom-Header", "Value": header_value}],
            }
        },
        ConfigurationSetName=config_set,
        EmailTags=[{"Name": "campaign", "Value": campaign_value}],
    )["MessageId"]
    assert message_id, "SendEmail must return a MessageId for an accepted message"

    dimensions = [
        {"Name": "ses:configuration-set", "Value": config_set},
        {"Name": "campaign", "Value": campaign_value},
        {"Name": "X-Custom-Header", "Value": header_value},
    ]

    def _window_end():
        return time.time() + 60

    total = _poll_until(
        lambda: _metric_sum(cw, "Send", dimensions, start - 60, _window_end()),
        lambda v: v is not None,
        timeout_s=_METRIC_POLL_TIMEOUT_S,
        interval_s=_METRIC_POLL_INTERVAL_S,
        description=(
            f"AWS/SES Send metric resolved for dimensions ses:configuration-set={config_set!r}, "
            f"campaign={campaign_value!r}, X-Custom-Header={header_value!r}"
        ),
    )
    assert total == 1, (
        f"expected exactly 1 Send datapoint for this message's unique dimension combination, "
        f"got {total!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
