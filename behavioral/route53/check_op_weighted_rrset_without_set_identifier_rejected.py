"""op-weighted-rrset-without-set-identifier-rejected."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "op-weighted-rrset-without-set-identifier-rejected"
GROUP = 'resource-record-sets'
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


def _error_code_and_message(fn, what):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A weighted record set without SetIdentifier is rejected with InvalidInput.
    A legal weighted pair at the same name and type is created first, so the refusal is about
    the missing field, not about every weighted CREATE at this name."""
    r53 = ctx.client("route53")
    resp = _create_zone(ctx, r53, name=_zone_name(ctx, "chk-op-weight"))
    zone_id = resp["HostedZone"]["Id"]
    record_name = "weighted." + resp["HostedZone"]["Name"]

    def _weighted(set_id, weight, value):
        return {
            "Name": record_name, "Type": "A", "TTL": 60,
            "SetIdentifier": set_id, "Weight": weight,
            "ResourceRecords": [{"Value": value}],
        }

    # --- positive control: a legal weighted group can exist at this name and type. ---
    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {"Action": "CREATE", "ResourceRecordSet": _weighted("blue", 100, "192.0.2.161")},
                {"Action": "CREATE", "ResourceRecordSet": _weighted("green", 50, "192.0.2.162")},
            ]
        },
    )
    control_group = [r for r in _list_all_record_sets(r53, zone_id) if r["Name"] == record_name]
    assert {r["SetIdentifier"] for r in control_group} == {"blue", "green"}, (
        f"the positive control group must round-trip both SetIdentifiers: {control_group}"
    )

    # --- break exactly one thing: a third sibling supplies Weight but omits SetIdentifier. ---
    code, msg = _error_code_and_message(
        lambda: r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": record_name,
                            "Type": "A",
                            "TTL": 60,
                            # Weight supplied but SetIdentifier omitted -> invalid
                            "Weight": 50,
                            "ResourceRecords": [{"Value": "192.0.2.160"}],
                        },
                    }
                ]
            },
        ),
        f"CREATE of a weighted record at {record_name} with a Weight but no SetIdentifier",
    )
    assert code == "InvalidInput", (
        f"expected InvalidInput for weighted rrset without SetIdentifier, got {code}: {msg}"
    )
    expected_message = (
        f"Invalid request: Missing field 'SetIdentifier' in Change with "
        f"[Action=CREATE, Name={record_name}, Type=A, SetIdentifier=null]"
    )
    assert msg == expected_message, f"expected message {expected_message!r}, got {msg!r}"

    # the refused CREATE must not have joined the group, and the legal pair must be untouched
    after = [r for r in _list_all_record_sets(r53, zone_id) if r["Name"] == record_name]
    assert len(after) == 2, f"the refused CREATE must not add a third sibling: {after}"
    assert {r["SetIdentifier"] for r in after} == {"blue", "green"}, (
        f"the positive control group must be unaffected by the refusal: {after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
