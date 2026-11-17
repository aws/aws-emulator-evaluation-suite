"""test-dns-answer-private-zone-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-dns-answer-private-zone-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx):
    raw = ctx.unique_name("sim2real-behav-zone").lower().replace("_", "-")
    # example.com/.org/.net are reserved by AWS for public zones; use a non-reserved suffix.
    return f"{raw}.sim2real-probe-zone.com."


def _poll_insync(r53, change_id, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        resp = r53.get_change(Id=change_id)
        if resp["ChangeInfo"]["Status"] == "INSYNC":
            return resp
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for INSYNC; last status={resp['ChangeInfo']['Status']}"
            )
        time.sleep(interval_s)


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


def _empty_and_delete_zone(r53, zone_id, apex_name):
    for rrs in _list_all_record_sets(r53, zone_id):
        if rrs["Name"] == apex_name and rrs["Type"] in ("NS", "SOA"):
            continue
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
        )
    r53.delete_hosted_zone(Id=zone_id)


def _expect_error(fn, what):
    """Require fn to raise ClientError; return (code, message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestDNSAnswer, which only supports public hosted zones, rejects a query against a
    private hosted zone with InvalidInput; the identical query against a public zone succeeds.
    """
    r53 = ctx.client("route53")
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda v=vpc_id: ec2.delete_vpc(VpcId=v))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    private_name = _zone_name(ctx)
    private_resp = r53.create_hosted_zone(
        Name=private_name,
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "behavioral-check", "PrivateZone": True},
        VPC={"VPCRegion": ctx.region, "VPCId": vpc_id},
    )
    private_zone_id = private_resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=private_zone_id, n=private_name: _empty_and_delete_zone(r53, z, n))

    public_name = _zone_name(ctx)
    public_resp = r53.create_hosted_zone(
        Name=public_name,
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "behavioral-check", "PrivateZone": False},
    )
    public_zone_id = public_resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=public_zone_id, n=public_name: _empty_and_delete_zone(r53, z, n))
    _poll_insync(r53, public_resp["ChangeInfo"]["Id"])

    # --- break exactly one thing: query the private zone. ---
    code, msg = _expect_error(
        lambda: r53.test_dns_answer(HostedZoneId=private_zone_id, RecordName=private_name, RecordType="SOA"),
        f"TestDNSAnswer against the private zone {private_name}",
    )
    assert code == "InvalidInput", f"expected InvalidInput querying a private zone, got {code}: {msg}"
    expected_message = "Cannot send DNS query to a Private Hosted Zone."
    assert msg == expected_message, f"expected message {expected_message!r}, got {msg!r}"

    # --- control: the identical query against a public zone succeeds. ---
    answer = r53.test_dns_answer(HostedZoneId=public_zone_id, RecordName=public_name, RecordType="SOA")
    assert answer["ResponseCode"] == "NOERROR", (
        f"expected NOERROR querying the public zone's own SOA, got {answer['ResponseCode']}: {answer}"
    )
    assert answer["RecordType"] == "SOA", f"RecordType must be echoed: {answer}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
