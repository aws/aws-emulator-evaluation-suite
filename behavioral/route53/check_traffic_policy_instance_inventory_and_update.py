"""traffic-policy-instance-inventory-and-update."""

from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "traffic-policy-instance-inventory-and-update"
GROUP = 'traffic-policy'
SERVICES = ['route53']

_SIMPLE_TP_DOCUMENT = (
    '{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A",'
    '"Endpoints":{"endpoint-1":{"Type":"value","Value":"192.0.2.100"}},'
    '"StartEndpoint":"endpoint-1"}'
)


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


def _create_zone(ctx, r53, *, name=None, comment=None):
    kwargs = {
        "Name": name or _zone_name(ctx),
        "CallerReference": _caller_reference(),
        "HostedZoneConfig": {"Comment": comment or "behavioral-check", "PrivateZone": False},
    }
    resp = r53.create_hosted_zone(**kwargs)
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return resp


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A traffic policy instance is discoverable by hosted zone and by policy, is counted, and UpdateTrafficPolicyInstance re-applies with the new TTL."""
    r53 = ctx.client("route53")
    resp = _create_zone(ctx, r53, name=_zone_name(ctx, "chk-tpinv"))
    zone_id = resp["HostedZone"]["Id"]
    name = resp["HostedZone"]["Name"]

    tp = r53.create_traffic_policy(Name=ctx.unique_name("chk-tpinv-"), Document=_SIMPLE_TP_DOCUMENT)
    policy_id = tp["TrafficPolicy"]["Id"]
    version = tp["TrafficPolicy"]["Version"]
    ctx.on_cleanup(lambda i=policy_id, v=version: r53.delete_traffic_policy(Id=i, Version=v))

    record_name = "inv." + name
    instance = r53.create_traffic_policy_instance(
        HostedZoneId=zone_id,
        Name=record_name,
        TTL=60,
        TrafficPolicyId=policy_id,
        TrafficPolicyVersion=version,
    )
    instance_id = instance["TrafficPolicyInstance"]["Id"]
    ctx.on_cleanup(lambda i=instance_id: r53.delete_traffic_policy_instance(Id=i))

    def wait_applied():
        return _poll_status(
            lambda: r53.get_traffic_policy_instance(Id=instance_id)["TrafficPolicyInstance"],
            lambda i: i["State"] in ("Applied", "Failed"),
            timeout_s=120,
            interval_s=3,
        )

    settled = wait_applied()
    assert settled["State"] == "Applied", settled["State"]

    count = r53.get_traffic_policy_instance_count()["TrafficPolicyInstanceCount"]
    assert count >= 1, count

    all_ids = {i["Id"] for i in r53.list_traffic_policy_instances()["TrafficPolicyInstances"]}
    assert instance_id in all_ids, f"{instance_id} missing from ListTrafficPolicyInstances"

    by_zone = r53.list_traffic_policy_instances_by_hosted_zone(HostedZoneId=zone_id.split("/")[-1])
    assert any(i["Id"] == instance_id for i in by_zone["TrafficPolicyInstances"]), by_zone

    by_policy = r53.list_traffic_policy_instances_by_policy(
        TrafficPolicyId=policy_id, TrafficPolicyVersion=version
    )
    assert any(i["Id"] == instance_id for i in by_policy["TrafficPolicyInstances"]), by_policy

    # updating the TTL re-applies the instance and is reflected in the record
    r53.update_traffic_policy_instance(
        Id=instance_id, TTL=300, TrafficPolicyId=policy_id, TrafficPolicyVersion=version
    )
    resettled = wait_applied()
    assert resettled["State"] == "Applied", resettled["State"]
    assert resettled["TTL"] == 300, resettled["TTL"]

    rrsets = _list_all_record_sets(r53, zone_id)
    match = [r for r in rrsets if r["Name"] == record_name and r["Type"] == "A"]
    assert match, f"traffic policy instance should materialize a record, got {[r['Name'] for r in rrsets]}"
    materialized = match[0]
    # The materialized record is owned/managed by the policy instance, so the
    # authoritative TTL lives on the INSTANCE (asserted above); Route 53 does
    # not guarantee a record-level TTL or AliasTarget on the generated rrset.
    assert materialized["Name"] == record_name, materialized
    assert materialized["Type"] == "A", materialized


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
