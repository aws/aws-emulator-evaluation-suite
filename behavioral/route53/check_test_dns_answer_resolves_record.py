"""test-dns-answer-resolves-record."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "test-dns-answer-resolves-record"
GROUP = 'resource-record-sets'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    # example.com/.org/.net are reserved by AWS for public zones; use a non-reserved suffix.
    return f"{raw}.sim2real-probe-zone.com."


def _poll_status(probe, done, timeout_s=60.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for condition; last response={last}"
            )
        time.sleep(interval_s)


def _wait_insync(r53, change_id, timeout_s=90, interval_s=2.0):
    return _poll_status(
        lambda: r53.get_change(Id=change_id),
        lambda resp: resp["ChangeInfo"]["Status"] == "INSYNC",
        timeout_s=timeout_s, interval_s=interval_s,
    )


def _list_all_record_sets(r53, zone_id):
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
    try:
        for rrs in _list_all_record_sets(r53, zone_id):
            if rrs["Type"] in ("NS", "SOA"):
                continue
            try:
                r53.change_resource_record_sets(
                    HostedZoneId=zone_id,
                    ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "HostedZoneNotFound",
                    "NoSuchHealthCheck",
                    "NoSuchHostedZone",
                ):
                    raise
        r53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHealthCheck",
            "NoSuchHostedZone",
        ):
            raise


def _change_a(r53, zone_id, action, name, value):
    return r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{
            "Action": action,
            "ResourceRecordSet": {
                "Name": name, "Type": "A", "TTL": 60, "ResourceRecords": [{"Value": value}],
            },
        }]},
    )


def _error(fn):
    """(Error.Code, HTTP status, Error.Message) of the ClientError fn raises; RAISES on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_vpc(ctx):
    # Route 53 validates VPC existence, so a real VPC is required (fake ids are rejected).
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda v=vpc_id: ec2.delete_vpc(VpcId=v))
    # private hosted zone association requires DNS support/hostnames on the VPC
    try:
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    except Exception:
        pass
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc")}],
    )
    return vpc_id


def _create_zone(ctx, r53, *, private=False, vpc_id=None, vpc_region=None,
                 name=None, comment=None):
    kwargs = {
        "Name": name or _zone_name(ctx),
        "CallerReference": _caller_reference(),
        "HostedZoneConfig": {"Comment": comment or "behavioral-check", "PrivateZone": private},
    }
    if private:
        kwargs["VPC"] = {
            "VPCRegion": vpc_region or ctx.region,
            "VPCId": vpc_id or _create_vpc(ctx),
        }
    resp = r53.create_hosted_zone(**kwargs)
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return resp


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestDNSAnswer resolves a freshly-created record set and returns the full response
    envelope (RecordData, RecordType, RecordName and Nameserver), not just a NOERROR code."""
    r53 = ctx.client("route53")
    resp = _create_zone(ctx, r53)
    zone_id = resp["HostedZone"]["Id"]
    zone_name = resp["HostedZone"]["Name"]
    record_name = f"probe.{zone_name}"

    c1 = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": "192.0.2.77"}],
                    },
                }
            ]
        },
    )
    _wait_insync(r53, c1["ChangeInfo"]["Id"])

    answer = r53.test_dns_answer(HostedZoneId=zone_id, RecordName=record_name, RecordType="A")
    assert answer["ResponseCode"] == "NOERROR", (
        f"expected NOERROR for a record just created, got {answer['ResponseCode']}: {answer}"
    )
    assert answer["RecordData"] == ["192.0.2.77"], (
        f"expected RecordData=['192.0.2.77'], got {answer['RecordData']}: {answer}"
    )
    assert answer["RecordType"] == "A", f"RecordType must be echoed: {answer}"
    assert answer["RecordName"].rstrip(".") == record_name.rstrip("."), (
        f"RecordName must echo the queried name: {answer}"
    )
    assert answer["Nameserver"], f"Nameserver must name the server that answered: {answer}"

    # UPSERT replaces the served value.
    _wait_insync(r53, _change_a(r53, zone_id, "UPSERT", record_name, "192.0.2.78")["ChangeInfo"]["Id"])
    answer = r53.test_dns_answer(HostedZoneId=zone_id, RecordName=record_name, RecordType="A")
    assert answer["RecordData"] == ["192.0.2.78"], (
        f"expected the UPSERTed RecordData=['192.0.2.78'], got {answer['RecordData']}: {answer}"
    )

    # DELETE: the name stops resolving, is no longer listed, and a second DELETE is refused.
    _wait_insync(r53, _change_a(r53, zone_id, "DELETE", record_name, "192.0.2.78")["ChangeInfo"]["Id"])
    answer = r53.test_dns_answer(HostedZoneId=zone_id, RecordName=record_name, RecordType="A")
    assert answer["ResponseCode"] == "NXDOMAIN", (
        f"expected NXDOMAIN for the deleted record, got {answer['ResponseCode']}: {answer}"
    )
    listed = r53.list_resource_record_sets(
        HostedZoneId=zone_id, StartRecordName=record_name, StartRecordType="A", MaxItems="1"
    )["ResourceRecordSets"]
    assert not any(
        r["Type"] == "A" and r["Name"].rstrip(".") == record_name.rstrip(".") for r in listed
    ), f"the deleted A record {record_name} is still listed: {listed!r}"
    code, status, message = _error(lambda: _change_a(r53, zone_id, "DELETE", record_name, "192.0.2.78"))
    assert code == "InvalidChangeBatch", f"a second DELETE of the record must be refused, got {code!r}"
    assert status == 400, f"expected HTTP 400 for the second DELETE, got {status!r}"
    expected_message = f"[Tried to delete resource record set [name='{record_name}', type='A'] but it was not found]"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
