"""dns-validated-certificate-issues-under-a-delegated-zone."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dns-validated-certificate-issues-under-a-delegated-zone"
GROUP = "state-machine"
SERVICES = ["acm"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}

def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); RAISE on deadline (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _domain_zone(ctx, route53):
    """(zone id, apex) of the publicly delegated baseline zone, the only zone ACM can validate in."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_id = z["Id"].rsplit("/", 1)[-1]
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=zone_id
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                return zone_id, z["Name"].rstrip(".")
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has "
        "no delegated zone to validate a certificate in"
    )


def _change_record(route53, zone_id, action, record):
    return route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": record["Name"],
                        "Type": record["Type"],
                        "TTL": 60,
                        "ResourceRecords": [{"Value": record["Value"]}],
                    },
                }
            ]
        },
    )["ChangeInfo"]["Id"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """A DNS-validated certificate whose validation CNAME is published in a publicly delegated zone
    moves from PENDING_VALIDATION to ISSUED (validation SUCCESS, AMAZON_ISSUED, unused) and is
    listed under ListCertificates(ISSUED)."""
    acm = ctx.client("acm")
    route53 = ctx.client("route53")
    zone_id, apex = _domain_zone(ctx, route53)
    # ACM caps the first domain name at 64 octets; under the baseline zone that leaves about 17
    # for this label.
    name = f"sim2real{uuid.uuid4().hex[:8]}.{apex}"
    assert len(name) <= 64, f"certificate name {len(name)} octets exceeds ACM's 64: {name!r}"

    cert_arn = acm.request_certificate(
        DomainName=name,
        ValidationMethod="DNS",
        IdempotencyToken=uuid.uuid4().hex[:24],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]

    def _detail():
        return acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]

    detail = _poll_until(
        _detail,
        lambda d: "ResourceRecord" in (d.get("DomainValidationOptions") or [{}])[0],
        timeout_s=180,
        interval_s=5,
        description=f"ACM publishing the DNS validation CNAME for {name!r}",
    )
    assert detail["Status"] == "PENDING_VALIDATION", (
        f"a fresh DNS-validated certificate starts PENDING_VALIDATION; got {detail['Status']!r}"
    )
    record = detail["DomainValidationOptions"][0]["ResourceRecord"]
    assert record["Type"] == "CNAME", f"ACM's DNS challenge must be a CNAME; got {record!r}"

    change_id = _change_record(route53, zone_id, "UPSERT", record)

    def _delete_record():
        try:
            _change_record(route53, zone_id, "DELETE", record)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "HostedZoneNotFound",
                "NoSuchHealthCheck",
                "NoSuchHostedZone",
            ):
                raise

    # Registered before the certificate's delete so it runs after it (LIFO): renewal reuses the
    # record while the certificate exists.
    ctx.on_cleanup(_delete_record)
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    _poll_until(
        lambda: route53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda status: status == "INSYNC",
        timeout_s=180,
        interval_s=5,
        description=f"Route 53 propagating the validation CNAME in zone {zone_id}",
    )

    issued = _poll_until(
        _detail,
        lambda d: d["Status"] != "PENDING_VALIDATION",
        timeout_s=900,
        interval_s=15,
        description=f"ACM validating {name!r} through the delegated zone {apex!r}",
    )
    assert issued["Status"] == "ISSUED", (
        f"with its validation CNAME publicly resolvable the certificate must reach ISSUED; got "
        f"{issued['Status']!r} (FailureReason {issued.get('FailureReason')!r})"
    )
    option = issued["DomainValidationOptions"][0]
    assert option["ValidationStatus"] == "SUCCESS", (
        f"the per-domain validation must read SUCCESS once issued; got {option!r}"
    )
    assert issued["Type"] == "AMAZON_ISSUED", f"Type must be AMAZON_ISSUED; got {issued['Type']!r}"
    assert issued["InUseBy"] == [], (
        f"a fresh certificate is in use by nothing; got {issued['InUseBy']!r}"
    )
    assert issued["NotBefore"] < issued["NotAfter"], (
        f"validity window inverted: {issued['NotBefore']!r} .. {issued['NotAfter']!r}"
    )

    listed = {
        s["CertificateArn"]
        for page in acm.get_paginator("list_certificates").paginate(CertificateStatuses=["ISSUED"])
        for s in page["CertificateSummaryList"]
    }
    assert cert_arn in listed, (
        "the issued certificate must be indexed under ListCertificates(ISSUED)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
