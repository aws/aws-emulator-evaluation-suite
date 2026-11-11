"""overly-permissive-delete-non-empty-hosted-zone."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "overly-permissive-delete-non-empty-hosted-zone"
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


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] DeleteHostedZone must fail while non-NS/SOA record sets remain in the zone."""
    r53 = ctx.client("route53")

    # positive control: DeleteHostedZone succeeds on an empty zone, so the rejection below is
    # not indistinguishable from a target that fails every DeleteHostedZone call.
    control = _create_zone(ctx, r53, name=_zone_name(ctx, prefix="ctrl"), comment="positive-control")
    control_id = control["HostedZone"]["Id"]
    r53.delete_hosted_zone(Id=control_id)
    control_gone, control_gone_message = _error_code(lambda: r53.get_hosted_zone(Id=control_id))
    assert control_gone == "NoSuchHostedZone", control_gone
    expected = f"No hosted zone found with ID: {control_id.split('/')[-1]}"
    assert control_gone_message == expected, f"expected message {expected!r}, got {control_gone_message!r}"

    zone = _create_zone(ctx, r53)
    zone_id = zone["HostedZone"]["Id"]
    record_name = f"blocker.{zone['HostedZone']['Name']}"
    change = {
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": record_name,
            "Type": "A",
            "TTL": 60,
            "ResourceRecords": [{"Value": "192.0.2.99"}],
        },
    }

    c1 = r53.change_resource_record_sets(
        HostedZoneId=zone_id, ChangeBatch={"Changes": [change]},
    )
    _wait_insync(r53, c1["ChangeInfo"]["Id"])

    code, message = _error_code(lambda: r53.delete_hosted_zone(Id=zone_id))
    assert code == "HostedZoneNotEmpty", code
    expected = (
        "The specified hosted zone contains resource record sets other than the default SOA and "
        "NS records and so cannot be deleted. Delete all non-default records and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # zone must still exist and be gettable after the rejected delete
    got = r53.get_hosted_zone(Id=zone_id)
    assert got["HostedZone"]["Id"] == zone_id, (
        f"zone {zone_id} unexpectedly missing after a rejected delete: {got}"
    )

    # restore: remove the only blocker, then the identical delete call must now succeed
    delete_change = dict(change, Action="DELETE")
    c2 = r53.change_resource_record_sets(
        HostedZoneId=zone_id, ChangeBatch={"Changes": [delete_change]},
    )
    _wait_insync(r53, c2["ChangeInfo"]["Id"])

    r53.delete_hosted_zone(Id=zone_id)

    gone_code, gone_message = _error_code(lambda: r53.get_hosted_zone(Id=zone_id))
    assert gone_code == "NoSuchHostedZone", gone_code
    expected = f"No hosted zone found with ID: {zone_id.split('/')[-1]}"
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    mutation_code, mutation_message = _error_code(
        lambda: r53.change_resource_record_sets(
            HostedZoneId=zone_id, ChangeBatch={"Changes": [dict(change)]},
        )
    )
    assert mutation_code == "NoSuchHostedZone", mutation_code
    expected = f"No hosted zone found with ID: {zone_id.split('/')[-1]}"
    assert mutation_message == expected, f"expected message {expected!r}, got {mutation_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
