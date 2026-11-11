"""hosted-zone-inventory-and-comment-update."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "hosted-zone-inventory-and-comment-update"
GROUP = 'hosted-zone'
SERVICES = ['route53']

#: Fresh resources tried before a concurrent change elsewhere in the account counts as a failure.
_ATTEMPTS = 3


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


def _create_zone(ctx, r53, *, name=None, comment=None):
    kwargs = {
        "Name": name or _zone_name(ctx),
        "CallerReference": _caller_reference(),
        "HostedZoneConfig": {"Comment": comment or "behavioral-check", "PrivateZone": False},
    }
    resp = r53.create_hosted_zone(**kwargs)
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    # ResourceId for tagging APIs is the bare zone id without the "/hostedzone/" prefix.
    r53.change_tags_for_resource(
        ResourceType="hostedzone",
        ResourceId=zone_id.split("/")[-1],
        AddTags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    return resp


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _settled_count(probe, expected, *, timeout_s=30.0, interval_s=2.0):
    """probe() once it equals ``expected``, else the last value read at the deadline; the count
    is eventually consistent."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if last == expected or time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new zone is listed, counted, and its comment update is visible via GetHostedZone.

    Unknown and deleted zone ids return NoSuchHostedZone for GetHostedZone and comment updates.
    """
    r53 = ctx.client("route53")
    # GetHostedZoneCount is account-wide, so a zone another run creates or deletes meanwhile moves
    # it too: each attempt makes a fresh zone, and only a window in which the count moved by
    # exactly our own one is graded.
    for _ in range(_ATTEMPTS):
        before_count = r53.get_hosted_zone_count()["HostedZoneCount"]
        resp = _create_zone(ctx, r53, name=_zone_name(ctx, "chk-inv"))
        after_count = _settled_count(
            lambda: r53.get_hosted_zone_count()["HostedZoneCount"], before_count + 1
        )
        if after_count == before_count + 1:
            break
    zone_id = resp["HostedZone"]["Id"]
    name = resp["HostedZone"]["Name"]

    # full (paginated) listing must contain the new zone
    found = False
    kwargs: dict = {}
    while True:
        page = r53.list_hosted_zones(**kwargs)
        if any(z["Id"] == zone_id for z in page["HostedZones"]):
            found = True
            break
        if not page.get("IsTruncated"):
            break
        kwargs = {"Marker": page["NextMarker"]}
    assert found, f"{zone_id} missing from ListHostedZones"

    # name-ordered listing, seeked to our name, must return our zone first
    by_name = r53.list_hosted_zones_by_name(DNSName=name)["HostedZones"]
    assert by_name and by_name[0]["Id"] == zone_id, (
        f"ListHostedZonesByName(DNSName={name}) should start at our zone, got {[z['Name'] for z in by_name[:3]]}"
    )

    assert after_count == before_count + 1, (
        f"GetHostedZoneCount should increase by exactly 1, got {before_count} -> {after_count} "
        f"in the last of {_ATTEMPTS} attempts"
    )

    comment = "sim2real behavioral comment"
    r53.update_hosted_zone_comment(Id=zone_id, Comment=comment)
    got = r53.get_hosted_zone(Id=zone_id)["HostedZone"]
    assert got["Config"]["Comment"] == comment, got["Config"]

    # A zone id that does not exist must be a clean not-found.
    unknown_zone = "Z" + uuid.uuid4().hex[:20].upper()
    err = _client_error(lambda: r53.update_hosted_zone_comment(Id=unknown_zone, Comment="x"))
    assert err["Code"] == "NoSuchHostedZone", f"expected NoSuchHostedZone, got {err}"
    assert err["Message"] == f"No hosted zone found with ID: {unknown_zone}", err

    # Deleting the zone we created must make it independently unreadable and unmutable.
    r53.delete_hosted_zone(Id=zone_id)

    err = _client_error(lambda: r53.get_hosted_zone(Id=zone_id))
    assert err["Code"] == "NoSuchHostedZone", f"deleted zone {zone_id} still readable via GetHostedZone, got {err}"
    assert err["Message"] == f"No hosted zone found with ID: {zone_id.split('/')[-1]}", err

    err = _client_error(lambda: r53.update_hosted_zone_comment(Id=zone_id, Comment="post-delete"))
    assert err["Code"] == "NoSuchHostedZone", (
        f"UpdateHostedZoneComment on deleted zone {zone_id} should be NoSuchHostedZone, got {err}"
    )
    assert err["Message"] == f"No hosted zone found with ID: {zone_id.split('/')[-1]}", err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
