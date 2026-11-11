"""configuration-set-sending-disabled-blocks-v2-send-email-then-restored."""

from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "configuration-set-sending-disabled-blocks-v2-send-email-then-restored"
GROUP = "server-side"
SERVICES = ["sesv2"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


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


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _send_expect_paused(send_fn, *, timeout_s) -> str:
    """Retry `send_fn` until it is refused with SendingPausedException.

    The send path can enforce the disable flag slightly after GetConfigurationSet reports it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = send_fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "SendingPausedException":
                return exc.response["Error"]["Message"]
            raise
        time.sleep(2.0)
    raise AssertionError(
        f"send never became SendingPausedException within {timeout_s}s after disabling the "
        f"configuration set's sending; last SendEmail response was {last!r}"
    )


def _send_expect_success(send_fn, *, timeout_s):
    """Retry `send_fn` until it succeeds; the send path can lag a re-enable by a few seconds."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return send_fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "SendingPausedException":
                raise
            last_code = code
        time.sleep(2.0)
    raise AssertionError(
        f"send never succeeded within {timeout_s}s after re-enabling the configuration set's "
        f"sending; last error code was {last_code!r}"
    )


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """A fresh configuration set sends by default; disabling its sending makes GetConfigurationSet
    report it disabled and the next v2 SendEmail fail with SendingPausedException, and re-enabling
    restores both.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    domain = _sending_domain(ctx, route53, sesv2)
    sender = f"{ctx.unique_name('sim2real-')}@{domain}"

    config_set = ctx.unique_name("sim2real-behav-cspause-")
    sesv2.create_configuration_set(
        ConfigurationSetName=config_set, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))

    def _sending_enabled() -> bool:
        return sesv2.get_configuration_set(ConfigurationSetName=config_set)["SendingOptions"][
            "SendingEnabled"
        ]

    def _content(label: str) -> dict:
        return {
            "Simple": {
                "Subject": {"Data": f"sim2real {CHECK} {label}"},
                "Body": {"Text": {"Data": f"sim2real probe body ({label})"}},
            }
        }

    def _send(label: str):
        return sesv2.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
            Content=_content(label),
            ConfigurationSetName=config_set,
        )

    default_resp = _send("default-enabled")
    assert default_resp.get("MessageId"), (
        f"expected a MessageId sending through a fresh (default-enabled) configuration set, "
        f"got {default_resp!r}"
    )

    sesv2.put_configuration_set_sending_options(
        ConfigurationSetName=config_set, SendingEnabled=False
    )
    ctx.on_cleanup(
        lambda: sesv2.put_configuration_set_sending_options(
            ConfigurationSetName=config_set, SendingEnabled=True
        )
    )
    _poll_until(
        _sending_enabled,
        lambda v: v is False,
        timeout_s=30,
        description="GetConfigurationSet reflecting the disabled per-set sending state",
    )

    paused_message = _send_expect_paused(lambda: _send("while-disabled"), timeout_s=60)
    expected_paused = f"Sending is paused for configuration set {config_set}"
    assert paused_message == expected_paused, (
        f"SendingPausedException must carry the message {expected_paused!r}, got "
        f"{paused_message!r}"
    )

    sesv2.put_configuration_set_sending_options(
        ConfigurationSetName=config_set, SendingEnabled=True
    )
    _poll_until(
        _sending_enabled,
        lambda v: v is True,
        timeout_s=30,
        description="GetConfigurationSet reflecting the re-enabled per-set sending state",
    )

    restored_resp = _send_expect_success(lambda: _send("after-re-enable"), timeout_s=60)
    assert restored_resp.get("MessageId"), (
        f"expected a MessageId sending through the configuration set again after re-enabling "
        f"its sending, got {restored_resp!r}"
    )
    assert restored_resp["MessageId"] != default_resp["MessageId"], (
        "re-enabled send must mint its own MessageId, not reuse the earlier accepted one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
