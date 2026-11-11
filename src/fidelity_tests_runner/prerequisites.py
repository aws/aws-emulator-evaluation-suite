"""What a test declares it needs before it runs: a DNS baseline.

A test tagged ``requires:dns-baseline`` gets a tagged public hosted zone, an SES identity for its
domain and the identity's DKIM records, as the account it was recorded in has. Other tags need no
setup and are ignored here.
"""

import time
import uuid
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

#: A test that finds a public hosted zone by ``DNS_BASELINE_TAG``, with an SES identity on it.
REQUIRES_DNS_BASELINE = "requires:dns-baseline"

#: The tag a DNS baseline's public hosted zone carries; a test finds the zone by it.
DNS_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}

#: How long setup waits for the emulator to report the baseline's SES identity verified.
IDENTITY_VERIFY_WAIT_S = 30.0
_VERIFY_POLL_S = 0.5


def _tagged_baseline(route53) -> tuple[str, str] | None:
    """``(zone id, domain)`` of a public hosted zone carrying ``DNS_BASELINE_TAG``, or None."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones", []):
            if (zone.get("Config") or {}).get("PrivateZone"):
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            tags = route53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=zone_id)
            if DNS_BASELINE_TAG in tags.get("ResourceTagSet", {}).get("Tags", []):
                return zone_id, zone["Name"].rstrip(".")
    return None


def _dkim_records(sesv2, domain: str, created: dict[str, Any]) -> list[dict[str, Any]]:
    """The Easy DKIM CNAMEs for ``domain``'s SES identity; none when it reports no tokens."""
    tokens = (created.get("DkimAttributes") or {}).get("Tokens") or (
        sesv2.get_email_identity(EmailIdentity=domain).get("DkimAttributes") or {}
    ).get("Tokens")
    return [
        {
            "Name": f"{token}._domainkey.{domain}",
            "Type": "CNAME",
            "TTL": 1800,
            "ResourceRecords": [{"Value": f"{token}.dkim.amazonses.com"}],
        }
        for token in tokens or ()
    ]


def _change_records(route53, zone_id: str, action: str, records: Iterable[dict[str, Any]]) -> None:
    changes = [{"Action": action, "ResourceRecordSet": record} for record in records]
    route53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch={"Changes": changes})


def _await_verified(sesv2, domain: str) -> None:
    """Poll until ``domain``'s identity is verified for sending, at most the bound; never raises."""
    deadline = time.monotonic() + IDENTITY_VERIFY_WAIT_S
    while True:
        try:
            if sesv2.get_email_identity(EmailIdentity=domain).get("VerifiedForSendingStatus"):
                return
        except (BotoCoreError, ClientError):
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(_VERIFY_POLL_S, remaining))


@contextmanager
def dns_baseline(client_factory: Callable[[str], Any], name: str) -> Iterator[str]:
    """An emulator's DNS baseline for the block; yields its domain.

    A tagged zone the emulator already holds is used as is. Otherwise this creates the zone, an
    SES (v2) identity for its domain and the identity's DKIM records, waits up to
    ``IDENTITY_VERIFY_WAIT_S`` for the identity to verify, and deletes all three after the block.
    """
    route53, sesv2 = client_factory("route53"), client_factory("sesv2")
    existing = _tagged_baseline(route53)
    if existing:
        yield existing[1]
        return
    domain = f"{name}.example.net"
    zone = route53.create_hosted_zone(Name=domain, CallerReference=str(uuid.uuid4()))
    zone_id = zone["HostedZone"]["Id"].rsplit("/", 1)[-1]
    identity, records = False, []

    def teardown() -> None:
        """Delete the identity, then its records (a zone with them is not empty), then the zone."""
        if identity:
            sesv2.delete_email_identity(EmailIdentity=domain)
        if records:
            _change_records(route53, zone_id, "DELETE", records)
        route53.delete_hosted_zone(Id=zone_id)

    try:
        route53.change_tags_for_resource(
            ResourceType="hostedzone", ResourceId=zone_id, AddTags=[DNS_BASELINE_TAG]
        )
        created = sesv2.create_email_identity(EmailIdentity=domain)
        identity = True
        records = _dkim_records(sesv2, domain, created)
        if records:
            _change_records(route53, zone_id, "UPSERT", records)
    except BaseException as exc:
        try:
            teardown()
        except Exception as undo:  # the setup error is the one raised
            exc.add_note(f"undoing the DNS baseline failed too: {undo!r}")
        raise
    _await_verified(sesv2, domain)
    try:
        yield domain
    finally:
        teardown()


@contextmanager
def prepare_check(
    tags: Iterable[str],
    client_factory: Callable[[str], Any],
    *,
    unique_name: Callable[[str], str] | None = None,
) -> Iterator[None]:
    """Set up what the test's tags require for the block: its DNS baseline, if tagged."""
    if REQUIRES_DNS_BASELINE not in tuple(tags):
        yield
        return
    name = (unique_name or (lambda p: f"{p}{uuid.uuid4().hex[:12]}"))("sim2real-baseline-")
    with dns_baseline(client_factory, name):
        yield
