"""rrset-delete-removes-only-target."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-delete-removes-only-target"
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
    """DELETE removes exactly the targeted record set, leaving an unrelated record and the
    zone's own NS/SOA untouched -- and the deleted record set cannot be deleted a second time."""
    r53 = ctx.client("route53")
    resp = _create_zone(ctx, r53)
    zone_id = resp["HostedZone"]["Id"]
    zone_name = resp["HostedZone"]["Name"]
    target_name = f"api.{zone_name}"
    control_name = f"www.{zone_name}"
    target = {"Name": target_name, "Type": "A", "TTL": 60, "ResourceRecords": [{"Value": "192.0.2.55"}]}
    control = {"Name": control_name, "Type": "A", "TTL": 60, "ResourceRecords": [{"Value": "192.0.2.66"}]}

    c1 = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [
            {"Action": "CREATE", "ResourceRecordSet": target},
            {"Action": "CREATE", "ResourceRecordSet": control},
        ]},
    )
    _wait_insync(r53, c1["ChangeInfo"]["Id"])
    before = _list_all_record_sets(r53, zone_id)
    assert any(r["Name"] == target_name for r in before), (
        f"expected {target_name} present after CREATE, got {before}"
    )
    assert any(r["Name"] == control_name for r in before), (
        f"expected control record {control_name} present after CREATE, got {before}"
    )

    c2 = r53.change_resource_record_sets(
        HostedZoneId=zone_id, ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": target}]}
    )
    _wait_insync(r53, c2["ChangeInfo"]["Id"])

    after = _list_all_record_sets(r53, zone_id)
    assert not any(r["Name"] == target_name for r in after), (
        f"expected {target_name} gone after DELETE, still present in {after}"
    )
    control_after = [r for r in after if r["Name"] == control_name]
    assert len(control_after) == 1 and control_after[0]["ResourceRecords"] == control["ResourceRecords"], (
        f"unrelated record {control_name} must survive the target's DELETE untouched, got {control_after}"
    )
    types = sorted(r["Type"] for r in after)
    assert types == ["A", "NS", "SOA"], (
        f"expected only the control A record plus the zone's own NS/SOA to remain, got {types}"
    )

    # the deleted record set is not just absent from the list -- it is unusable: the identical
    # DELETE, resubmitted, must now be rejected rather than silently no-op or re-create it.
    try:
        r53.change_resource_record_sets(
            HostedZoneId=zone_id, ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": target}]}
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "InvalidChangeBatch", (
            f"expected InvalidChangeBatch re-deleting an already-deleted record, got {code}"
        )
        expected = f"[Tried to delete resource record set [name='{target_name}', type='A'] but it was not found]"
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            f"expected re-DELETE of the already-deleted {target_name} to be rejected, but it succeeded"
        )
    after2 = _list_all_record_sets(r53, zone_id)
    assert not any(r["Name"] == target_name for r in after2), (
        f"a rejected re-DELETE must not conjure {target_name} back into existence: {after2}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
