"""configuration-set-tracking-options-lifecycle-with-verified-domain."""

from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "configuration-set-tracking-options-lifecycle-with-verified-domain"
GROUP = "configuration-set"
SERVICES = ["ses"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


def _verified_apex(ctx, route53, sesv2) -> str:
    """Return the account's tagged, SES-verified public domain."""
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


def _redirect_label(apex: str) -> str:
    # SES accepts a CustomRedirectDomain under a verified parent identity; no new identity needed.
    return f"click.sim2real{uuid.uuid4().hex[:8]}.{apex}"


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """Tracking options store a CustomRedirectDomain under a verified apex; a duplicate Create is
    refused as TrackingOptionsAlreadyExists without change; Update replaces it; Delete removes it.
    """
    ses = ctx.client("ses")
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    apex = _verified_apex(ctx, route53, sesv2)

    config_set_name = ctx.unique_name("sim2real-behav-cstrk-")
    ses.create_configuration_set(ConfigurationSet={"Name": config_set_name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=config_set_name))

    def _tracking_domain() -> str | None:
        described = ses.describe_configuration_set(
            ConfigurationSetName=config_set_name,
            ConfigurationSetAttributeNames=["trackingOptions"],
        )
        return described.get("TrackingOptions", {}).get("CustomRedirectDomain")

    assert _tracking_domain() is None, (
        f"freshly created configuration set already has a tracking domain: {_tracking_domain()!r}"
    )

    domain_a = _redirect_label(apex)
    ses.create_configuration_set_tracking_options(
        ConfigurationSetName=config_set_name,
        TrackingOptions={"CustomRedirectDomain": domain_a},
    )
    stored_a = _tracking_domain()
    assert stored_a == domain_a, (
        f"CreateConfigurationSetTrackingOptions under a verified apex must store the domain "
        f"as given; expected {domain_a!r}, got {stored_a!r}"
    )

    domain_b = _redirect_label(apex)
    dup = _error(
        lambda: ses.create_configuration_set_tracking_options(
            ConfigurationSetName=config_set_name,
            TrackingOptions={"CustomRedirectDomain": domain_b},
        )
    )
    expected_dup = (
        "TrackingOptionsAlreadyExists",
        f"There is already a tracking options for configuration set <{config_set_name}>",
    )
    assert dup == expected_dup, (
        f"a second Create on a set that already has tracking options must be rejected "
        f"{expected_dup!r}, got {dup!r}"
    )
    assert _tracking_domain() == domain_a, (
        f"the rejected duplicate Create must leave the originally stored domain untouched; "
        f"expected {domain_a!r}, got {_tracking_domain()!r}"
    )

    ses.update_configuration_set_tracking_options(
        ConfigurationSetName=config_set_name,
        TrackingOptions={"CustomRedirectDomain": domain_b},
    )
    stored_b = _tracking_domain()
    assert stored_b == domain_b, (
        f"UpdateConfigurationSetTrackingOptions must replace the stored domain; expected "
        f"{domain_b!r}, got {stored_b!r}"
    )

    ses.delete_configuration_set_tracking_options(ConfigurationSetName=config_set_name)
    assert _tracking_domain() is None, (
        f"DeleteConfigurationSetTrackingOptions must leave no TrackingOptions object; "
        f"DescribeConfigurationSet still reports {_tracking_domain()!r}"
    )

    ses.create_configuration_set_tracking_options(
        ConfigurationSetName=config_set_name,
        TrackingOptions={"CustomRedirectDomain": domain_a},
    )
    assert _tracking_domain() == domain_a, (
        f"TrackingOptionsAlreadyExists blocks a Create only while tracking options are live; "
        f"the identical Create must succeed again once Delete freed it, expected {domain_a!r}, "
        f"got {_tracking_domain()!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
