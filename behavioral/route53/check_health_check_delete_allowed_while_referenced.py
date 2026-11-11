"""health-check-delete-allowed-while-referenced."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "health-check-delete-allowed-while-referenced"
GROUP = 'health-check'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    # AWS refuses example.com/.org/.net for public zones; the reserved .invalid TLD is accepted.
    return f"{raw}.invalid."


def _health_check_fqdn(ctx):
    """A name under the reserved .invalid TLD: it never resolves, so the health check probes no host."""
    return f"{ctx.unique_name('sim2real-behav-hc').lower()}.invalid"


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


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")



def _delete_health_check_if_present(r53, hc_id):
    """Teardown: the run deletes the health check itself, so a not-found here is success."""
    try:
        r53.delete_health_check(HealthCheckId=hc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHealthCheck":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A health check referenced by a record set can be deleted; HealthCheckInUse is not in use.

    The referencing record set survives and keeps its now-dangling HealthCheckId.
    """
    r53 = ctx.client("route53")
    resp = r53.create_health_check(
        CallerReference=_caller_reference(),
        HealthCheckConfig={"FullyQualifiedDomainName": _health_check_fqdn(ctx), "Port": 80, "Type": "HTTP",
                            "RequestInterval": 30, "FailureThreshold": 3},
    )
    hc_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda i=hc_id: _delete_health_check_if_present(r53, i))

    zone = _create_zone(ctx, r53)
    zone_id = zone["HostedZone"]["Id"]
    record_name = f"weighted.{zone['HostedZone']['Name']}"
    rrset = {
        "Name": record_name,
        "Type": "A",
        "SetIdentifier": "primary",
        "Weight": 100,
        "TTL": 60,
        "ResourceRecords": [{"Value": "192.0.2.47"}],
        "HealthCheckId": hc_id,
    }
    c1 = r53.change_resource_record_sets(
        HostedZoneId=zone_id, ChangeBatch={"Changes": [{"Action": "CREATE", "ResourceRecordSet": rrset}]}
    )
    _wait_insync(r53, c1["ChangeInfo"]["Id"])

    # deleting an actively-referenced health check is permitted
    r53.delete_health_check(HealthCheckId=hc_id)

    err = _client_error(lambda: r53.get_health_check(HealthCheckId=hc_id))
    assert err["Code"] == "NoSuchHealthCheck", err
    assert err["Message"] == f"A health check with id {hc_id} does not exist.", err

    # a mutation on the dead id fails too, not just a read
    err = _client_error(
        lambda: r53.update_health_check(HealthCheckId=hc_id, HealthCheckVersion=1, ResourcePath="/gone")
    )
    assert err["Code"] == "NoSuchHealthCheck", err
    assert err["Message"] == f"A health check with id {hc_id} does not exist.", err

    # the record set is untouched and still carries the dangling reference
    rrsets = _list_all_record_sets(r53, zone_id)
    match = [r for r in rrsets if r["Name"] == record_name and r["Type"] == "A"]
    assert len(match) == 1, rrsets
    assert match[0].get("HealthCheckId") == hc_id, match[0]

    c2 = r53.change_resource_record_sets(
        HostedZoneId=zone_id, ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": match[0]}]}
    )
    _wait_insync(r53, c2["ChangeInfo"]["Id"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
