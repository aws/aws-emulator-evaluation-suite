"""private-zone-multi-vpc-association."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "private-zone-multi-vpc-association"
GROUP = 'vpc-association'
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


def _client_error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second VPC can be associated with a private zone, and disassociating one leaves the other intact."""
    r53 = ctx.client("route53")
    vpc1 = _create_vpc(ctx)
    zone = _create_zone(ctx, r53, private=True, vpc_id=vpc1)
    zone_id = zone["HostedZone"]["Id"]

    vpc2 = _create_vpc(ctx)
    r53.associate_vpc_with_hosted_zone(HostedZoneId=zone_id, VPC={"VPCId": vpc2, "VPCRegion": ctx.region})

    # The VPC membership recorded on the hosted zone updates as soon as the
    # association is accepted; the returned ChangeInfo only tracks DNS propagation
    # (INSYNC), which routinely lags well past a minute and is NOT what this check
    # asserts. Poll the actual observable — the zone's VPC list.
    def zone_vpc_ids():
        return {v["VPCId"] for v in r53.get_hosted_zone(Id=zone_id).get("VPCs", [])}

    vpc_ids = _poll_status(zone_vpc_ids, lambda ids: {vpc1, vpc2} <= ids, timeout_s=60, interval_s=2)
    assert {vpc1, vpc2} <= vpc_ids, vpc_ids

    r53.disassociate_vpc_from_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCId": vpc2, "VPCRegion": ctx.region}
    )

    vpc_ids2 = _poll_status(zone_vpc_ids, lambda ids: vpc2 not in ids, timeout_s=60, interval_s=2)
    assert vpc1 in vpc_ids2, vpc_ids2
    assert vpc2 not in vpc_ids2, vpc_ids2

    # The disassociation must be a real state change, not merely accepted-and-ignored:
    # repeating it against the now-unassociated VPC is rejected, not silently re-accepted.
    code, message = _client_error(
        lambda: r53.disassociate_vpc_from_hosted_zone(
            HostedZoneId=zone_id, VPC={"VPCId": vpc2, "VPCRegion": ctx.region}
        )
    )
    assert code == "VPCAssociationNotFound", code
    expected_message = f"No VPC association for {vpc2}:{ctx.region} to hosted zone {zone_id.rsplit('/', 1)[-1]}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
