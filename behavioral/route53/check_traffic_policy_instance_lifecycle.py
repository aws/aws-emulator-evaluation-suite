"""traffic-policy-instance-lifecycle."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "traffic-policy-instance-lifecycle"
GROUP = 'traffic-policy'
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
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_instance_if_present(r53, tpi_id):
    """Teardown: the check deletes the instance itself, so a not-found here is the clean case."""
    try:
        r53.delete_traffic_policy_instance(Id=tpi_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchTrafficPolicyInstance":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrafficPolicyInstance materializes record sets and transitions State Creating->Applied."""
    r53 = ctx.client("route53")
    doc = '{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A","Endpoints":{"e1":{"Type":"value","Value":"192.0.2.5"}},"StartEndpoint":"e1"}'
    tp = r53.create_traffic_policy(Name=ctx.unique_name("sim2real-behav-tp-inst"), Document=doc)
    tp_id = tp["TrafficPolicy"]["Id"]
    tp_version = tp["TrafficPolicy"]["Version"]
    ctx.on_cleanup(lambda i=tp_id, v=tp_version: r53.delete_traffic_policy(Id=i, Version=v))

    zone = _create_zone(ctx, r53)
    zone_id = zone["HostedZone"]["Id"]
    instance_name = f"tpi.{zone['HostedZone']['Name']}"

    resp = r53.create_traffic_policy_instance(
        HostedZoneId=zone_id, Name=instance_name, TTL=60, TrafficPolicyId=tp_id, TrafficPolicyVersion=tp_version
    )
    tpi_id = resp["TrafficPolicyInstance"]["Id"]
    ctx.on_cleanup(lambda i=tpi_id: _delete_instance_if_present(r53, i))
    assert resp["TrafficPolicyInstance"]["State"] in ("Creating", "Applied"), resp["TrafficPolicyInstance"]["State"]

    def probe():
        return r53.get_traffic_policy_instance(Id=tpi_id)

    def applied(r):
        return r["TrafficPolicyInstance"]["State"] == "Applied"

    final = _poll_status(probe, applied, timeout_s=120, interval_s=3.0)
    assert final["TrafficPolicyInstance"]["State"] == "Applied", final["TrafficPolicyInstance"]["State"]

    rrsets = _list_all_record_sets(r53, zone_id)
    assert any(r["Name"] == instance_name for r in rrsets), rrsets

    r53.delete_traffic_policy_instance(Id=tpi_id)

    # Deletion is ASYNCHRONOUS: the instance stays readable for a short window after
    # DeleteTrafficPolicyInstance returns, so poll for the terminal NoSuchTrafficPolicyInstance.
    def read():
        try:
            state = r53.get_traffic_policy_instance(Id=tpi_id)["TrafficPolicyInstance"]["State"]
        except ClientError as exc:
            return ("error", exc.response.get("Error", {}).get("Code"))
        return ("state", state)

    outcome = _poll_status(read, lambda r: r[0] == "error", timeout_s=120, interval_s=3.0)
    assert outcome == ("error", "NoSuchTrafficPolicyInstance"), outcome

    # A mutation on the now-dead id must also fail, not silently resurrect or no-op.
    second_delete_code = _error_code(lambda: r53.delete_traffic_policy_instance(Id=tpi_id))
    assert second_delete_code == "NoSuchTrafficPolicyInstance", second_delete_code


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
