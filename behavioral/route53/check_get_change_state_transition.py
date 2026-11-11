"""get-change-state-transition."""

from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "get-change-state-transition"
GROUP = 'hosted-zone'
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetChange for the change id returned by CreateHostedZone reads PENDING or INSYNC, settles
    INSYNC under the same id, and INSYNC is stable on a fresh read."""
    r53 = ctx.client("route53")
    resp = _create_zone(ctx, r53)
    change_id = resp["ChangeInfo"]["Id"]

    # PENDING lasts until the change reaches every Route 53 DNS server; no duration is
    # documented, so the first read may already be INSYNC.
    initial_status = r53.get_change(Id=change_id)["ChangeInfo"]["Status"]
    assert initial_status in ("PENDING", "INSYNC"), (
        f"expected a freshly created hosted zone's change to read back PENDING or INSYNC, got {initial_status!r}"
    )

    final = _wait_insync(r53, change_id)
    final_id = final["ChangeInfo"]["Id"]
    assert final_id == change_id, (
        f"expected the change id to stay {change_id!r} across polling, got {final_id!r}"
    )

    # Independent re-read: INSYNC is terminal and must not regress on a fresh read that
    # is not gated by _wait_insync's own done-condition.
    confirm = r53.get_change(Id=change_id)
    confirm_status = confirm["ChangeInfo"]["Status"]
    assert confirm_status == "INSYNC", (
        f"expected INSYNC to be stable on a fresh independent read, got {confirm_status!r}"
    )
    confirm_id = confirm["ChangeInfo"]["Id"]
    assert confirm_id == change_id, (
        f"expected the change id to stay {change_id!r} on the confirm read, got {confirm_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
