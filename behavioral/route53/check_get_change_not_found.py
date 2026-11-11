"""get-change-not-found."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "get-change-not-found"
GROUP = 'hosted-zone'
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


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetChange fails with NoSuchChange for a well-formed but unknown change id.

    A real change id from the same run succeeds, so the failure is specific to the unknown id.
    """
    r53 = ctx.client("route53")

    resp = r53.create_hosted_zone(
        Name=_zone_name(ctx),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "behavioral-check", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    real_change_id = resp["ChangeInfo"]["Id"]

    positive = r53.get_change(Id=real_change_id)
    assert positive["ChangeInfo"]["Id"] == real_change_id, (
        f"positive control: expected GetChange to echo {real_change_id!r}, "
        f"got {positive['ChangeInfo'].get('Id')!r}"
    )

    bogus_id = "C" + uuid.uuid4().hex[:20].upper()
    err = _client_error(lambda: r53.get_change(Id=bogus_id))
    assert err["Code"] == "NoSuchChange", f"expected NoSuchChange, got {err}"
    assert err["Message"] == f"Could not find resource with ID: {bogus_id}", err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
