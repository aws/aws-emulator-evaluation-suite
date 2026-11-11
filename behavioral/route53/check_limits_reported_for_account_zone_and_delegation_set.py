"""limits-reported-for-account-zone-and-delegation-set."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "limits-reported-for-account-zone-and-delegation-set"
GROUP = 'hosted-zone'
SERVICES = ['route53']

#: Fresh resources tried before a concurrent change elsewhere in the account counts as a failure.
_ATTEMPTS = 3


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    # AWS refuses example.com/.org/.net for public zones; the reserved .invalid TLD is accepted.
    return f"{raw}.invalid."


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


def _create_zone(ctx, r53, *, name=None, comment=None, delegation_set_id=None):
    kwargs = {
        "Name": name or _zone_name(ctx),
        "CallerReference": _caller_reference(),
        "HostedZoneConfig": {"Comment": comment or "behavioral-check", "PrivateZone": False},
    }
    if delegation_set_id:
        kwargs["DelegationSetId"] = delegation_set_id
    resp = r53.create_hosted_zone(**kwargs)
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return resp


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, because
    a target accepting a call AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_health_check_quiet(r53, hc_id):
    try:
        r53.delete_health_check(HealthCheckId=hc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHealthCheck":
            raise


def _poll_until_count(probe, expected, *, timeout_s=30.0, interval_s=2.0, description="count"):
    # the limit APIs' Count is control-plane state, not DNS data, but we give it a bounded
    # retry window rather than assuming synchronicity -- eventual consistency here would
    # otherwise read as a real defect.
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description}: expected Count to reach {expected} within {timeout_s}s, last saw {last}"
    )


def _settled_count(probe, expected, *, timeout_s=30.0, interval_s=2.0):
    """probe() once it equals ``expected``, else the last value read at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if last == expected or time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountLimit, GetHostedZoneLimit and GetReusableDelegationSetLimit report a positive
    limit, and each Count moves by exactly +1 when the matching resource is created."""
    r53 = ctx.client("route53")

    # --- account-level: MAX_HEALTH_CHECKS_BY_OWNER must move by exactly +1 when we create one.
    # The Count is account-wide, so a health check another run creates or deletes meanwhile moves
    # it too: each attempt makes a fresh health check, and only a window in which the Count moved
    # by exactly our own one is graded. ---
    for _ in range(_ATTEMPTS):
        before_acct = r53.get_account_limit(Type="MAX_HEALTH_CHECKS_BY_OWNER")
        assert before_acct["Limit"]["Type"] == "MAX_HEALTH_CHECKS_BY_OWNER", before_acct["Limit"]
        assert before_acct["Limit"]["Value"] > 0, before_acct["Limit"]

        hc = r53.create_health_check(
            CallerReference=_caller_reference(),
            HealthCheckConfig={
                "FullyQualifiedDomainName": ctx.unique_name("sim2real-behav-hc-")
                + ".invalid",
                "Port": 80,
                "Type": "HTTP",
                "RequestInterval": 30,
                "FailureThreshold": 3,
            },
        )
        hc_id = hc["HealthCheck"]["Id"]
        ctx.on_cleanup(lambda i=hc_id: _delete_health_check_quiet(r53, i))

        acct_count = _settled_count(
            lambda: r53.get_account_limit(Type="MAX_HEALTH_CHECKS_BY_OWNER")["Count"],
            before_acct["Count"] + 1,
        )
        if acct_count == before_acct["Count"] + 1:
            break
    assert acct_count == before_acct["Count"] + 1, (
        f"MAX_HEALTH_CHECKS_BY_OWNER Count after creating one health check: expected "
        f"{before_acct['Count'] + 1}, last saw {acct_count} in the last of {_ATTEMPTS} attempts"
    )

    # --- zone-level: MAX_RRSETS_BY_ZONE must move by exactly +1 when we add one record set ---
    resp = _create_zone(ctx, r53, name=_zone_name(ctx, "chk-limit"))
    zone_id = resp["HostedZone"]["Id"]
    zone_name = resp["HostedZone"]["Name"]
    # ResourceId for the limit APIs is the bare id without the "/hostedzone/" prefix
    bare_zone_id = zone_id.split("/")[-1]
    before_zone = r53.get_hosted_zone_limit(Type="MAX_RRSETS_BY_ZONE", HostedZoneId=bare_zone_id)
    assert before_zone["Limit"]["Value"] > 0, before_zone["Limit"]
    # a fresh zone always holds at least its default NS + SOA records
    assert before_zone["Count"] >= 2, (
        f"expected the default NS+SOA to be counted, got {before_zone['Count']}"
    )

    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [{
                "Action": "CREATE",
                "ResourceRecordSet": {
                    "Name": f"limit-probe.{zone_name}",
                    "Type": "TXT",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": '"limit-probe"'}],
                },
            }]
        },
    )
    _poll_until_count(
        lambda: r53.get_hosted_zone_limit(Type="MAX_RRSETS_BY_ZONE", HostedZoneId=bare_zone_id)["Count"],
        before_zone["Count"] + 1,
        description="MAX_RRSETS_BY_ZONE Count after adding one record set",
    )

    # --- delegation-set-level: MAX_ZONES_BY_REUSABLE_DELEGATION_SET must move by exactly +1 when
    # a zone is created under it ---
    ds = r53.create_reusable_delegation_set(CallerReference=_caller_reference())
    ds_id = ds["DelegationSet"]["Id"]
    ctx.on_cleanup(lambda i=ds_id: r53.delete_reusable_delegation_set(Id=i))
    bare_ds_id = ds_id.split("/")[-1]
    before_ds = r53.get_reusable_delegation_set_limit(
        Type="MAX_ZONES_BY_REUSABLE_DELEGATION_SET", DelegationSetId=bare_ds_id
    )
    assert before_ds["Limit"]["Value"] > 0, before_ds["Limit"]
    assert before_ds["Count"] == 0, f"a brand-new delegation set should host 0 zones, got {before_ds['Count']}"

    ds_resp = _create_zone(ctx, r53, name=_zone_name(ctx, "chk-limit-ds"), delegation_set_id=ds_id)
    assert ds_resp["DelegationSet"]["Id"] == ds_id, ds_resp.get("DelegationSet")
    _poll_until_count(
        lambda: r53.get_reusable_delegation_set_limit(
            Type="MAX_ZONES_BY_REUSABLE_DELEGATION_SET", DelegationSetId=bare_ds_id
        )["Count"],
        before_ds["Count"] + 1,
        description="MAX_ZONES_BY_REUSABLE_DELEGATION_SET Count after creating one zone under it",
    )

    # unknown zone must not silently return a limit
    unknown_zone_id = "Z" + uuid.uuid4().hex[:20].upper()
    code, message = _client_error(
        lambda: r53.get_hosted_zone_limit(Type="MAX_RRSETS_BY_ZONE", HostedZoneId=unknown_zone_id)
    )
    assert code == "NoSuchHostedZone", f"expected NoSuchHostedZone, got {code}"
    expected_message = f"No hosted zone found with ID: {unknown_zone_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
