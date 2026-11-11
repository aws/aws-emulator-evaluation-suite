"""delegation-set-in-use-blocks-delete."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delegation-set-in-use-blocks-delete"
GROUP = 'delegation-set'
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


def _delete_if_present(fn):
    """Teardown delete that tolerates the delegation set already being gone (the check deletes it)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchDelegationSet":
            raise


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A reusable delegation set still bound to a hosted zone cannot be deleted."""
    r53 = ctx.client("route53")
    ds = r53.create_reusable_delegation_set(CallerReference=_caller_reference())
    ds_id = ds["DelegationSet"]["Id"]
    ctx.on_cleanup(lambda i=ds_id: _delete_if_present(lambda: r53.delete_reusable_delegation_set(Id=i)))

    zone = r53.create_hosted_zone(
        Name=_zone_name(ctx),
        CallerReference=_caller_reference(),
        DelegationSetId=ds_id,
        HostedZoneConfig={"Comment": "ds-in-use", "PrivateZone": False},
    )
    zone_id = zone["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))

    code, message = _error(lambda: r53.delete_reusable_delegation_set(Id=ds_id))
    assert code == "DelegationSetInUse", code
    expected = "The specified delegation set contains associated hosted zones."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The blocked delete had no effect: the delegation set is still there.
    still_there = r53.get_reusable_delegation_set(Id=ds_id)
    assert still_there["DelegationSet"]["Id"] == ds_id, still_there

    r53.delete_hosted_zone(Id=zone_id)

    zone_gone, zone_gone_message = _error(lambda: r53.get_hosted_zone(Id=zone_id))
    assert zone_gone == "NoSuchHostedZone", zone_gone
    expected = f"No hosted zone found with ID: {zone_id.split('/')[-1]}"
    assert zone_gone_message == expected, f"expected message {expected!r}, got {zone_gone_message!r}"

    # Restore: with the zone gone, the identical delete call now succeeds.
    r53.delete_reusable_delegation_set(Id=ds_id)

    # AWS's not-found message for a delegation set is the bare delegation set id.
    bare_ds_id = ds_id.split("/")[-1]
    ds_gone, ds_gone_message = _error(lambda: r53.get_reusable_delegation_set(Id=ds_id))
    assert ds_gone == "NoSuchDelegationSet", ds_gone
    assert ds_gone_message == bare_ds_id, f"expected message {bare_ds_id!r}, got {ds_gone_message!r}"

    redelete_code, redelete_message = _error(lambda: r53.delete_reusable_delegation_set(Id=ds_id))
    assert redelete_code == "NoSuchDelegationSet", redelete_code
    assert redelete_message == bare_ds_id, f"expected message {bare_ds_id!r}, got {redelete_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
