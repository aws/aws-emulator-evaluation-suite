"""test-dns-answer-invalid-record-type-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "test-dns-answer-invalid-record-type-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestDNSAnswer rejects an unsupported record type query with InvalidInput instead of
    returning a stale or empty answer; a well-formed query against the same record still
    succeeds (in-file positive control)."""
    r53 = ctx.client("route53")

    zone_name = f"{ctx.unique_name('sim2reals-r53-')}.com."
    zone_resp = r53.create_hosted_zone(Name=zone_name, CallerReference=str(uuid.uuid4()))
    zone_id = zone_resp["HostedZone"]["Id"]
    r53.change_tags_for_resource(
        ResourceType="hostedzone",
        ResourceId=zone_id.split("/")[-1],
        AddTags=[{"Key": "sim2real", "Value": "route53-test-dns-answer-invalid-record-type-rejected"}],
    )
    ctx.on_cleanup(lambda: _empty_and_delete_zone(r53, zone_id))

    change = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": zone_name,
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": "192.0.2.1"}],
                    },
                }
            ]
        },
    )
    _wait_for_insync(r53, change["ChangeInfo"]["Id"], timeout_s=120.0)

    # Positive control: a well-formed A-record query resolves to what we created.
    good = _poll_test_dns_answer(r53, zone_id, zone_name, "A", timeout_s=60.0)
    assert good["RecordType"] == "A", f"expected RecordType 'A', got {good!r}"
    assert "192.0.2.1" in good["RecordData"], good["RecordData"]

    # Negative: an unsupported/malformed record type must be rejected with InvalidInput.
    # RecordType is an enum in the botocore model, so the client normally rejects it
    # before a request is even sent. Bypass ONLY client-side parameter validation (by
    # temporarily unwrapping the ParamValidationDecorator botocore wraps the serializer
    # in) on this SAME signed client so the real server-side check is exercised, without
    # touching credentials/signing (a fresh client here previously broke sigv4 signing).
    err = _client_error(
        lambda: _call_unvalidated(
            r53, "test_dns_answer",
            HostedZoneId=zone_id, RecordName=zone_name, RecordType="NOTAREALTYPE",
        )
    )
    assert err.get("Code") == "InvalidInput", err
    assert err.get("Message") == (
        "1 validation error detected: Value 'NOTAREALTYPE' at 'recordType' failed to satisfy "
        "constraint: Member must satisfy enum value set: [AAAA, A, SVCB, CAA, NS, SOA, TLSA, "
        "SPF, HTTPS, MX, PTR, CNAME, DS, TXT, SSHFP, SRV, NAPTR]"
    ), err


def _call_unvalidated(client, method_name, **kwargs):
    serializer = client._serializer
    unwrapped = getattr(serializer, "_serializer", serializer)
    original = client._serializer
    client._serializer = unwrapped
    try:
        return getattr(client, method_name)(**kwargs)
    finally:
        client._serializer = original


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected InvalidInput, but the call SUCCEEDED and returned {result!r}")


def _list_non_apex(r53, zone_id):
    out = []
    kwargs = {"HostedZoneId": zone_id}
    while True:
        resp = r53.list_resource_record_sets(**kwargs)
        out.extend(r for r in resp["ResourceRecordSets"] if r["Type"] not in ("NS", "SOA"))
        if not resp.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]


def _empty_and_delete_zone(r53, zone_id, timeout_s=45.0, interval_s=2.0):
    """DeleteHostedZone fails with HostedZoneNotEmpty while any non-NS/SOA record set remains,
    and a leaked zone bills $0.50/month with no proration -- so the A record this check created
    must be deleted first, and any failure here must raise rather than be swallowed."""
    leftovers = _list_non_apex(r53, zone_id)
    for rrs in leftovers:
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
        )
    deadline = time.monotonic() + timeout_s
    while _list_non_apex(r53, zone_id):
        if time.monotonic() >= deadline:
            raise AssertionError(f"non-apex record sets in {zone_id} never cleared before DeleteHostedZone")
        time.sleep(interval_s)
    r53.delete_hosted_zone(Id=zone_id)


def _wait_for_insync(r53, change_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = r53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return
        time.sleep(interval_s)
    raise AssertionError(f"change {change_id} never reached INSYNC, last status={status}")


def _poll_test_dns_answer(r53, zone_id, record_name, record_type, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = r53.test_dns_answer(
            HostedZoneId=zone_id, RecordName=record_name, RecordType=record_type
        )
        last = resp
        if resp.get("ResponseCode") == "NOERROR" and resp.get("RecordData"):
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"TestDNSAnswer never returned a resolved answer, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
