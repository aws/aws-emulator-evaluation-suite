"""overly-permissive-disassociate-last-vpc."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "overly-permissive-disassociate-last-vpc"
GROUP = 'vpc-association'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    # example.com/.org/.net are reserved by AWS for public zones; use a non-reserved suffix.
    return f"{raw}.sim2real-probe-zone.com."


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


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(probe, done, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for condition; last={last}")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Disassociating the only VPC from a private zone fails instead of orphaning the zone.
    Once a second VPC is associated, the identical disassociate succeeds, so the refusal is
    specific to the last-VPC condition."""
    r53 = ctx.client("route53")
    vpc_id = _create_vpc(ctx)
    zone = _create_zone(ctx, r53, private=True, vpc_id=vpc_id)
    zone_id = zone["HostedZone"]["Id"]

    code, message = _error(
        lambda: r53.disassociate_vpc_from_hosted_zone(
            HostedZoneId=zone_id, VPC={"VPCId": vpc_id, "VPCRegion": ctx.region}
        )
    )
    assert code == "LastVPCAssociation", code
    expected = "Cannot remove last VPC association for private zone"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # zone must still be associated with the vpc afterwards
    got = r53.get_hosted_zone(Id=zone_id)
    vpc_ids = {v["VPCId"] for v in got["VPCs"]}
    assert vpc_id in vpc_ids, vpc_ids

    # restore: associate a second VPC, then the identical disassociate call now succeeds --
    # this is what tells "rejects removing the last VPC" apart from "rejects every disassociate
    # on this zone".
    vpc2 = _create_vpc(ctx)
    r53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCId": vpc2, "VPCRegion": ctx.region}
    )

    def _zone_vpc_ids():
        return {v["VPCId"] for v in r53.get_hosted_zone(Id=zone_id).get("VPCs", [])}

    both = _poll_until(_zone_vpc_ids, lambda ids: {vpc_id, vpc2} <= ids)
    assert {vpc_id, vpc2} <= both, both

    r53.disassociate_vpc_from_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCId": vpc_id, "VPCRegion": ctx.region}
    )
    after = _poll_until(_zone_vpc_ids, lambda ids: vpc_id not in ids)
    assert vpc_id not in after, after
    assert vpc2 in after, after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
