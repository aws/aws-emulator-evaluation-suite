"""list-resource-record-sets-start-record-type-without-name-rejected."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "list-resource-record-sets-start-record-type-without-name-rejected"
GROUP = "resource-record-sets"
SERVICES = ["route53"]


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx):
    raw = ctx.unique_name("sim2real-behav-pgn").lower().replace("_", "-")
    return f"{raw}.example.test."


def _poll(probe, done, *, timeout_s, interval_s=2.0, what="condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last={last!r}")
        time.sleep(interval_s)


def _wait_insync(r53, change_id):
    return _poll(
        lambda: r53.get_change(Id=change_id),
        lambda resp: resp["ChangeInfo"]["Status"] == "INSYNC",
        timeout_s=90.0, interval_s=2.0, what=f"change {change_id} to reach INSYNC",
    )


def _list_all(r53, zone_id):
    out = []
    kwargs = {"HostedZoneId": zone_id}
    while True:
        resp = r53.list_resource_record_sets(**kwargs)
        out.extend(resp["ResourceRecordSets"])
        if not resp.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]
        if resp.get("NextRecordIdentifier"):
            kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]


def _empty_and_delete_zone(r53, zone_id):
    for rrs in _list_all(r53, zone_id):
        if rrs["Type"] in ("NS", "SOA"):
            continue
        try:
            r53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidChangeBatch", "NoSuchHostedZone"):
                raise
    try:
        r53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


def _create_zone(ctx, r53):
    resp = r53.create_hosted_zone(
        Name=_zone_name(ctx),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "pagination param validation", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return zone_id, resp["HostedZone"]["Name"]


def _error(fn):
    """(Code, Message) of the ClientError fn raises; RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


_ERR = ("InvalidInput", "")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListResourceRecordSets requires StartRecordName whenever StartRecordType is given; passing
    StartRecordType alone is rejected with InvalidInput rather than silently ignored.
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    record_name = f"www.{zone_name}"

    change_id = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": record_name, "Type": "A", "TTL": 60,
                "ResourceRecords": [{"Value": "203.0.113.21"}],
            },
        }]},
    )["ChangeInfo"]["Id"]
    _wait_insync(r53, change_id)

    # Positive control: the record's own name as the legal neighbour -- StartRecordName AND
    # StartRecordType together are a valid continuation token pair.
    page = r53.list_resource_record_sets(
        HostedZoneId=zone_id, StartRecordName=record_name, StartRecordType="A"
    )
    assert any(
        r["Name"] == record_name and r["Type"] == "A" for r in page["ResourceRecordSets"]
    ), f"StartRecordName+StartRecordType together must list from {record_name}: {page}"

    got = _error(lambda: r53.list_resource_record_sets(
        HostedZoneId=zone_id, StartRecordType="A"
    ))
    assert got == _ERR, f"expected {_ERR}, got {got}"

    # The record set itself is unaffected by the refused read.
    rrsets = _list_all(r53, zone_id)
    match = [r for r in rrsets if r["Name"] == record_name and r["Type"] == "A"]
    assert len(match) == 1, f"the record set must be untouched by the refused call: {match}"

    # Supplying the name again, identically to the positive control, succeeds.
    page = r53.list_resource_record_sets(
        HostedZoneId=zone_id, StartRecordName=record_name, StartRecordType="A"
    )
    assert any(
        r["Name"] == record_name and r["Type"] == "A" for r in page["ResourceRecordSets"]
    ), f"the identical valid call must still succeed after the refusal: {page}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
