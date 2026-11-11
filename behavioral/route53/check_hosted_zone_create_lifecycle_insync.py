"""hosted-zone-create-lifecycle-insync."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hosted-zone-create-lifecycle-insync"
GROUP = 'hosted-zone'
SERVICES = ['route53']

# Public hosted zones cannot be created under the RFC-2606 reserved domains
# (real AWS: "example.com. is reserved by AWS!"), so checks use a synthetic
# non-reserved suffix instead. Route 53 does not verify domain ownership, and
# these zones are never delegated, so they resolve for nobody.
_ZONE_SUFFIX = ".sim2real-behav-test.com."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created hosted zone's change converges to INSYNC with the default 4 NS servers and only
    NS/SOA records; once deleted the zone is gone for reads, the by-name listing and mutations."""
    r53 = ctx.client("route53")
    name = ctx.unique_name("sim2real-behav-chk-zone-") + _ZONE_SUFFIX
    resp = r53.create_hosted_zone(Name=name, CallerReference=_caller_reference(ctx))
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: _empty_and_delete_zone(r53, zone_id))

    status = _wait_for_change(r53, resp["ChangeInfo"]["Id"])
    assert status == "INSYNC", status

    got = r53.get_hosted_zone(Id=zone_id)
    assert got["HostedZone"]["Name"] == name, got["HostedZone"]["Name"]
    ns_records = list(got["DelegationSet"]["NameServers"])
    assert len(ns_records) == 4, f"expected the default 4-server delegation set, got {ns_records}"

    rrsets = r53.list_resource_record_sets(HostedZoneId=zone_id)["ResourceRecordSets"]
    types = sorted(r["Type"] for r in rrsets)
    assert types == ["NS", "SOA"], f"expected exactly one NS and one SOA record set, got {types}"

    r53.delete_hosted_zone(Id=zone_id)
    bare_zone_id = zone_id.split("/")[-1]
    read_code, read_status, read_message = _error(lambda: r53.get_hosted_zone(Id=zone_id))
    assert read_code == "NoSuchHostedZone", f"expected NoSuchHostedZone after delete, got {read_code}"
    assert isinstance(read_status, int) and 400 <= read_status < 500, f"expected HTTP 4xx from GetHostedZone after delete, got {read_status!r}"
    expected_message = f"No hosted zone found with ID: {bare_zone_id}"
    assert read_message == expected_message, f"expected the message {expected_message!r}, got {read_message!r}"

    listed = r53.list_hosted_zones_by_name(DNSName=name, MaxItems="1").get("HostedZones", [])
    assert all(z["Id"].split("/")[-1] != bare_zone_id for z in listed), (
        f"deleted zone {bare_zone_id} is still returned by ListHostedZonesByName: {listed!r}"
    )

    mutate_code, mutate_status, mutate_message = _error(
        lambda: r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": name,
                            "Type": "TXT",
                            "TTL": 60,
                            "ResourceRecords": [{"Value": '"unreachable"'}],
                        },
                    }
                ]
            },
        )
    )
    assert mutate_code == "NoSuchHostedZone", (
        f"expected NoSuchHostedZone mutating a deleted zone, got {mutate_code}"
    )
    assert isinstance(mutate_status, int) and 400 <= mutate_status < 500, f"expected HTTP 4xx mutating a deleted zone, got {mutate_status!r}"
    expected_message = f"No hosted zone found with ID: {bare_zone_id}"
    assert mutate_message == expected_message, f"expected the message {expected_message!r}, got {mutate_message!r}"


def _error(fn):
    """Call fn(); return the botocore (Error.Code, HTTP status, Error.Message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _caller_reference(ctx, prefix="r53") -> str:
    return ctx.unique_name(f"sim2real-behav-{prefix}-")


def _wait_for_change(r53, change_id, timeout_s=90, interval_s=2.0) -> str:
    """Poll GetChange until ChangeInfo.Status is INSYNC (or timeout)."""
    return _poll_until(
        lambda: r53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda status: status == "INSYNC",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"change {change_id} reaching INSYNC",
    )


def _empty_and_delete_zone(r53, zone_id):
    """Delete every non-apex-NS/SOA record so the zone can be deleted, then delete the zone."""
    kwargs = {"HostedZoneId": zone_id}
    try:
        while True:
            resp = r53.list_resource_record_sets(**kwargs)
            changes = [
                {"Action": "DELETE", "ResourceRecordSet": rrset}
                for rrset in resp.get("ResourceRecordSets", [])
                if rrset["Type"] not in ("NS", "SOA")
            ]
            if changes:
                try:
                    r53.change_resource_record_sets(
                        HostedZoneId=zone_id, ChangeBatch={"Changes": changes}
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "HostedZoneNotFound",
                        "NoSuchHealthCheck",
                        "NoSuchHostedZone",
                    ):
                        raise
            if not resp.get("IsTruncated"):
                break
            kwargs = {
                "HostedZoneId": zone_id,
                "StartRecordName": resp["NextRecordName"],
                "StartRecordType": resp["NextRecordType"],
            }
            if resp.get("NextRecordIdentifier"):
                kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHealthCheck",
            "NoSuchHostedZone",
        ):
            raise
    try:
        r53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
