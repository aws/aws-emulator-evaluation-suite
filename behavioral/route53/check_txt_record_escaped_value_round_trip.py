"""txt-record-escaped-value-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "txt-record-escaped-value-round-trip"
GROUP = "representation"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A TXT record value containing embedded quotes, backslashes, and unicode is
    written via ChangeResourceRecordSets and read back byte-identical via
    ListResourceRecordSets."""
    route53 = ctx.client("route53")

    zone_name = f"{ctx.unique_name('sim2real-txt-')}.com."
    zone = route53.create_hosted_zone(
        Name=zone_name, CallerReference=ctx.unique_name("caller-")
    )
    zone_id = zone["HostedZone"]["Id"]
    _poll_change_insync(ctx, zone["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_delete_zone(ctx, zone_id))
    route53.change_tags_for_resource(
        ResourceType="hostedzone",
        ResourceId=zone_id.split("/")[-1],
        AddTags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    record_name = f"txt.{zone_name}"
    # embedded double-quote, backslash, and unicode (café / 中文). Route 53's TXT
    # Value wire format only accepts printable ASCII within the quoted
    # character-string: a literal backslash must be written as \\, a literal
    # double-quote as \", and any non-ASCII character must be represented as its
    # UTF-8 bytes, each written \OOO (3-digit octal -- Route 53 rejects a 3-digit
    # decimal escape with IncompleteOctalEscapeSequence). Building this escaped
    # form here -- rather than submitting the raw unicode text -- is what lets the
    # round trip through ChangeResourceRecordSets / ListResourceRecordSets be
    # exercised.
    raw_content = 'embedded "quote" and backslash \\ and unicode café 中文'
    txt_value = _escape_txt_value(raw_content)

    change = route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "TXT",
                        "TTL": 300,
                        "ResourceRecords": [{"Value": txt_value}],
                    },
                }
            ]
        },
    )
    _poll_change_insync(ctx, change["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _delete_txt_record(ctx, zone_id, record_name, txt_value))

    rrsets = route53.list_resource_record_sets(HostedZoneId=zone_id)["ResourceRecordSets"]
    matching = [r for r in rrsets if r["Name"] == record_name and r["Type"] == "TXT"]
    assert len(matching) == 1, f"expected exactly one TXT record named {record_name!r}"
    values = matching[0]["ResourceRecords"]
    assert len(values) == 1, f"expected exactly one ResourceRecord value, got {values!r}"
    assert values[0]["Value"] == txt_value, (
        f"expected the TXT value read back byte-identical: sent {txt_value!r}, "
        f"got {values[0]['Value']!r}"
    )


def _escape_txt_value(raw: str) -> str:
    """Encode *raw* as a single Route 53 TXT character-string: wrapped in double
    quotes, with backslash/quote escaped and every non-ASCII-printable character
    represented as \\OOO (a 3-digit OCTAL escape) per UTF-8 byte -- Route 53
    rejects \\DDD decimal escapes with IncompleteOctalEscapeSequence."""
    out = []
    for ch in raw:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch.isprintable() and ord(ch) < 127:
            out.append(ch)
        else:
            for b in ch.encode("utf-8"):
                out.append(f"\\{b:03o}")
    return '"' + "".join(out) + '"'


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_change_insync(ctx, change_id, timeout_s=120.0) -> None:
    route53 = ctx.client("route53")
    _poll_until(
        lambda: route53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda s: s == "INSYNC",
        timeout_s=timeout_s,
        interval_s=3.0,
    )


def _delete_txt_record(ctx, zone_id, record_name, txt_value) -> None:
    route53 = ctx.client("route53")
    try:
        route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": record_name,
                            "Type": "TXT",
                            "TTL": 300,
                            "ResourceRecords": [{"Value": txt_value}],
                        },
                    }
                ]
            },
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHealthCheck",
            "NoSuchHostedZone",
        ):
            raise


def _safe_delete_zone(ctx, zone_id) -> None:
    # NoSuchHostedZone means a prior cleanup attempt already removed it -- idempotent,
    # safe to swallow. Anything else (e.g. HostedZoneNotEmpty because _delete_txt_record
    # above failed) must raise: swallowing it here would silently leak a zone that bills
    # $0.50/month forever with no signal in the run's output.
    route53 = ctx.client("route53")
    try:
        route53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchHostedZone":
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
