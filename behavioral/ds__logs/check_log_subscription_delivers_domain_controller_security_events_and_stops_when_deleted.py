"""log-subscription-delivers-domain-controller-security-events-and-stops-when-deleted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where Directory Service cannot place domain controllers (CreateMicrosoftAD: "Failed to
# locate Availability Zone"); subnets there are never offered to it. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "log-subscription-delivers-domain-controller-security-events-and-stops-when-deleted"
GROUP = "eventing"
SERVICES = ["ds", "logs"]
# Also drives ds-data (a separate signed endpoint) to produce the audited act.

_PASSWORD = "Sim2Real#Pass99"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}
_DIRECTORY_DEADLINE_S = 3600.0
_DATA_ACCESS_DEADLINE_S = 300.0
# Ceiling on each positive control (a forwarded event naming a user).
_DELIVERY_DEADLINE_S = 900.0
# Ceiling on the restore leg: a subscription re-created right after its delete can take longer
# than the first one to start forwarding.
_RESTORE_DEADLINE_S = 1800.0
_POLL_INTERVAL_S = 2.0
# CreateLogSubscription forwarded a user created seconds before it, so a user meant to stay
# unforwarded is created this long before each (re)subscription.
_FORWARDING_LOOKBACK_S = 300.0
# The withhold window is 3 * the measured positive-control latency, floored at the forwarding
# lookback (so a leaked event cannot hide behind it once the restore leg re-subscribes) and capped.
_MIN_ABSENCE_S = _FORWARDING_LOOKBACK_S
_MAX_ABSENCE_S = 2700.0


# Not-found / already-in-state codes of the teardown calls below (directory, data access, log
# subscription, log group, resource policy, ds-data user).
_GONE = frozenset({"EntityDoesNotExistException", "ResourceNotFoundException", "DirectoryInDesiredStateException"})


def _swallow_not_found(fn):
    """Run a teardown call: a resource already gone is fine; any other error raises. Cleanup only."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE:
            raise


def _refusal(fn, what: str) -> dict:
    """The refusal fn() raised, flattened over exc.response. RAISES on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return {**exc.response, **(exc.response.get("Error") or {})}
    raise AssertionError(
        f"{what} SUCCEEDED where real AWS refuses it; the response was {result!r}"
    )


def _poll(fn, pred, *, timeout_s: float, interval_s: float, what: str):
    """Poll fn() until pred(result). Raises on timeout, naming what it waited for."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observation was {last!r}"
            )
        time.sleep(interval_s)


def _capped(ctx, budget_s: float) -> float:
    """*budget_s*, capped by the time the run has left so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, max(0.0, left - 10.0))


def _outlast_lookback(dsdata, directory_id: str, user: str, what: str) -> None:
    """Let *user*'s creation event age past the forwarding lookback before a (re)subscription,
    re-reading the user throughout so a directory that goes unhealthy fails loudly."""
    # fixed-wait: the lookback CreateLogSubscription applies to recent events, not a state to poll
    deadline = time.monotonic() + _FORWARDING_LOOKBACK_S
    while True:
        read = dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=user)
        assert read.get("SAMAccountName") == user, (
            f"expected the {what} user to remain present before the subscription is (re)created, "
            f"expected {user!r}, got {read!r}"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(_POLL_INTERVAL_S)


def _describe_directory(ds, directory_id: str):
    try:
        found = ds.describe_directories(DirectoryIds=[directory_id])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
            return None
        raise
    descriptions = found.get("DirectoryDescriptions") or []
    return descriptions[0] if descriptions else None


def _events(logs, log_group_name: str, since_ms: int) -> list:
    """Every log event in the group since `since_ms`, across every stream and every page.

    Scans the whole group rather than a guessed stream name.
    """
    collected: list = []
    token = None
    while True:
        kwargs = {"logGroupName": log_group_name, "startTime": since_ms, "limit": 10000}
        if token:
            kwargs["nextToken"] = token
        page = logs.filter_log_events(**kwargs)
        collected.extend(page.get("events") or [])
        token = page.get("nextToken")
        if not token:
            return collected


def _mentions(events: list, needle: str) -> list:
    """Every event whose message contains `needle`; the audited event embeds the account name, so
    matching the message keeps the assertion independent of the log format."""
    return [event for event in events if needle in (event.get("message") or "")]


def _stored_bytes(logs, log_group_name: str) -> int:
    """The group's storedBytes, the second independent observable for the withhold leg."""
    described = logs.describe_log_groups(logGroupNamePrefix=log_group_name).get("logGroups") or []
    exact = [group for group in described if group.get("logGroupName") == log_group_name]
    assert exact, (
        f"expected DescribeLogGroups to return the log group this check created, expected "
        f"{log_group_name!r}, got {[g.get('logGroupName') for g in described]!r}"
    )
    return int(exact[0].get("storedBytes") or 0)


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """The account's shared network and two subnets in distinct AZs, as a Managed AD requires.

    A shared VPC rather than a per-check one, because the default VPC quota is five per region.
    """
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, (
        "expected this account to have a shared network, got none; a Managed Microsoft AD requires a "
        "VPC with two subnets in distinct availability zones"
    )
    vpc = vpcs[0]
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc["VpcId"]]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_zone: dict = {}
    for subnet in sorted(subnets, key=lambda x: x["SubnetId"]):
        by_zone.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    zones = sorted(by_zone)
    assert len(zones) >= 2, (
        f"expected >= 2 available zones with a subnet in each, got {len(zones)}: {by_zone!r} in "
        f"{vpc['VpcId']!r}"
    )
    return vpc["VpcId"], [by_zone[z] for z in zones[:2]]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:eventing", "dp:api", "plane:control", "plane:data", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """A ds-data user creation reaches the subscribed log group as a DC security event; users created
    before subscribing, or while it is deleted, never arrive, and re-subscribing restores delivery.
    """
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "expected STS to report the caller account id, got an empty value"

    # --- Directory. Owned by this check: a directory may hold only one log subscription.
    vpc_id, subnet_ids = _default_vpc_subnets(ec2, ctx=ctx)
    fqdn = f"{ctx.unique_name('sim2real-behav-')}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=fqdn, ShortName="SIM2REAL", Password=_PASSWORD, Edition="Standard",
        Description=f"sim2real behavioral {CHECK}",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": "behavioral"},
              {"Key": "sim2real-check", "Value": CHECK}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _swallow_not_found(
        lambda: ds.delete_directory(DirectoryId=directory_id)))
    created = _poll(
        lambda: _describe_directory(ds, directory_id) or {},
        lambda d: d.get("Stage") in _CREATE_TERMINAL,
        timeout_s=_capped(ctx, _DIRECTORY_DEADLINE_S), interval_s=_POLL_INTERVAL_S,
        what=f"directory {directory_id} to reach a terminal creation stage",
    )
    assert created.get("Stage") == "Active", (
        f"expected the directory to reach Stage 'Active' before any log forwarding is meaningful, "
        f"got {created.get('Stage')!r} (StageReason={created.get('StageReason')!r})"
    )

    ds.enable_directory_data_access(DirectoryId=directory_id)
    ctx.on_cleanup(lambda: _swallow_not_found(
        lambda: ds.disable_directory_data_access(DirectoryId=directory_id)))
    opened = _poll(
        lambda: ds.describe_directory_data_access(
            DirectoryId=directory_id).get("DataAccessStatus"),
        lambda s: s in ("Enabled", "Failed"),
        timeout_s=_capped(ctx, _DATA_ACCESS_DEADLINE_S), interval_s=_POLL_INTERVAL_S,
        what=f"DataAccessStatus on {directory_id} to settle so ds-data can produce audited acts",
    )
    assert opened == "Enabled", (
        f"expected EnableDirectoryDataAccess to drive DataAccessStatus to 'Enabled' so this check has "
        f"a way to trigger a domain-controller security event, got {opened!r}"
    )
    dsdata = ctx.client("ds-data")

    # --- The consumer: a log group, and the resource policy Directory Service needs to write to it.
    log_group_name = f"/aws/directoryservice/{ctx.unique_name('sim2real-ds-lg-')}"
    logs.create_log_group(
        logGroupName=log_group_name,
        tags={"sim2real": "behavioral", "sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _swallow_not_found(
        lambda: logs.delete_log_group(logGroupName=log_group_name)))
    policy_name = ctx.unique_name("sim2real-ds-logpolicy-")
    logs.put_resource_policy(policyName=policy_name, policyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DSLogSubscription",
            "Effect": "Allow",
            "Principal": {"Service": "ds.amazonaws.com"},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"arn:aws:logs:{ctx.region}:{account}:log-group:{log_group_name}:*",
        }],
    }))
    ctx.on_cleanup(lambda: _swallow_not_found(
        lambda: logs.delete_resource_policy(policyName=policy_name)))

    # --- LEG 0. Structural barrier: logs predating forwarding are documented as not transferred.
    before_subscription = ctx.unique_name("s2rPre")[:20]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: dsdata.delete_user(
        DirectoryId=directory_id, SAMAccountName=before_subscription)))
    started_ms = int(time.time() * 1000) - 60_000
    dsdata.create_user(DirectoryId=directory_id, SAMAccountName=before_subscription,
                       GivenName="Sim", Surname="Pre")
    # It really was created — otherwise "its event never arrived" would be trivially true.
    pre_read = dsdata.describe_user(
        DirectoryId=directory_id, SAMAccountName=before_subscription)
    assert pre_read.get("SAMAccountName") == before_subscription, (
        f"expected the pre-subscription user to actually exist in the directory, so that its ABSENCE "
        f"from the log group is a statement about forwarding rather than about the user, expected "
        f"{before_subscription!r}, got {pre_read!r}"
    )
    _outlast_lookback(dsdata, directory_id, before_subscription, "pre-subscription")

    # --- Subscribe, and assert the producer-side association exists before relying on it.
    ds.create_log_subscription(DirectoryId=directory_id, LogGroupName=log_group_name)
    ctx.on_cleanup(lambda: _swallow_not_found(
        lambda: ds.delete_log_subscription(DirectoryId=directory_id)))
    subscriptions = ds.list_log_subscriptions(
        DirectoryId=directory_id).get("LogSubscriptions") or []
    assert [s.get("LogGroupName") for s in subscriptions] == [log_group_name], (
        f"expected exactly one log subscription on {directory_id!r}, pointing at "
        f"{log_group_name!r}, got {subscriptions!r}"
    )

    # --- LEG 1. Positive control: a user created under the subscription is forwarded.
    subscribed_at = time.monotonic()
    after_subscription = ctx.unique_name("s2rPost")[:20]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: dsdata.delete_user(
        DirectoryId=directory_id, SAMAccountName=after_subscription)))
    dsdata.create_user(DirectoryId=directory_id, SAMAccountName=after_subscription,
                       GivenName="Sim", Surname="Post")
    delivered = _poll(
        lambda: _mentions(_events(logs, log_group_name, started_ms), after_subscription),
        lambda hits: bool(hits),
        timeout_s=_capped(ctx, _DELIVERY_DEADLINE_S), interval_s=_POLL_INTERVAL_S,
        what=f"a domain-controller security event naming {after_subscription!r} to be forwarded into "
             f"{log_group_name!r} — AWS documents log forwarding as delivering DC security logs, and "
             f"'Audit User Account Management' is one of the audited categories",
    )
    latency_s = time.monotonic() - subscribed_at
    assert delivered, (
        f"positive control failed: expected at least one forwarded event naming "
        f"{after_subscription!r} in {log_group_name!r}, got none after {latency_s:.0f}s"
    )

    # --- LEG 0 verdict, asserted after a proven delivery so it cannot pass because nothing arrived.
    all_events = _events(logs, log_group_name, started_ms)
    assert _mentions(all_events, before_subscription) == [], (
        f"expected the user created BEFORE the subscription existed to never be forwarded — AWS "
        f"documents that logs created before log forwarding is enabled are not transferred — but "
        f"{before_subscription!r} appears in "
        f"{[e.get('message', '')[:120] for e in _mentions(all_events, before_subscription)][:3]!r}"
    )

    # --- LEG 2. Withhold: delete the subscription.
    ds.delete_log_subscription(DirectoryId=directory_id)
    gone = ds.list_log_subscriptions(DirectoryId=directory_id).get("LogSubscriptions") or []
    assert [s for s in gone if s.get("LogGroupName") == log_group_name] == [], (
        f"expected DeleteLogSubscription to remove the association from ListLogSubscriptions before "
        f"the absence below means anything, got {gone!r}"
    )
    bytes_before = _stored_bytes(logs, log_group_name)
    withheld = ctx.unique_name("s2rHeld")[:20]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: dsdata.delete_user(
        DirectoryId=directory_id, SAMAccountName=withheld)))
    dsdata.create_user(DirectoryId=directory_id, SAMAccountName=withheld,
                       GivenName="Sim", Surname="Held")
    held_read = dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=withheld)
    assert held_read.get("SAMAccountName") == withheld, (
        f"expected the withheld user to actually exist, so its absence from the log group is a "
        f"statement about forwarding, expected {withheld!r}, got {held_read!r}"
    )
    # 3L: a window shorter than the measured latency would mistake slow delivery for no delivery.
    window_s = min(max(3.0 * latency_s, _MIN_ABSENCE_S), _MAX_ABSENCE_S)
    assert window_s >= latency_s, (
        f"expected the absence window ({window_s:.0f}s) to be at least the measured delivery latency "
        f"({latency_s:.0f}s); a shorter window cannot distinguish 'withheld' from 'slower'"
    )
    absence_deadline = time.monotonic() + _capped(ctx, window_s)
    while True:
        held_read = dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=withheld)
        assert held_read.get("SAMAccountName") == withheld, (
            f"expected the withheld user to remain present while its absence window runs, expected "
            f"{withheld!r}, got {held_read!r}"
        )
        seen = _mentions(_events(logs, log_group_name, started_ms), withheld)
        assert seen == [], (
            f"expected NO event naming {withheld!r} while the log subscription is deleted, but one "
            f"arrived after at most {window_s:.0f}s (3x the measured {latency_s:.0f}s delivery "
            f"latency): {[e.get('message', '')[:120] for e in seen][:3]!r}"
        )
        if time.monotonic() >= absence_deadline:
            break
        time.sleep(_POLL_INTERVAL_S)
    # Second independent observable: nothing was written to the group at all.
    bytes_after = _stored_bytes(logs, log_group_name)
    assert bytes_after == bytes_before, (
        f"expected the log group's storedBytes not to advance while the subscription is deleted over "
        f"the {window_s:.0f}s window — a second observable independent of the message scan — "
        f"expected {bytes_before}, got "
        f"{bytes_after}"
    )

    # --- LEG 3. Restore the subscription and demand delivery again.
    ds.create_log_subscription(DirectoryId=directory_id, LogGroupName=log_group_name)
    resumed = ctx.unique_name("s2rBack")[:20]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: dsdata.delete_user(
        DirectoryId=directory_id, SAMAccountName=resumed)))
    dsdata.create_user(DirectoryId=directory_id, SAMAccountName=resumed,
                       GivenName="Sim", Surname="Back")
    back = _poll(
        lambda: _mentions(_events(logs, log_group_name, started_ms), resumed),
        lambda hits: bool(hits),
        timeout_s=_capped(ctx, _RESTORE_DEADLINE_S), interval_s=_POLL_INTERVAL_S,
        what=f"delivery to resume for {resumed!r} after the subscription was re-created — the "
             f"restore beat, which is what separates a target that genuinely withholds from one that "
             f"has no delivery path at all",
    )
    assert back, (
        f"expected delivery to resume after re-creating the subscription, got no event naming "
        f"{resumed!r} within {_RESTORE_DEADLINE_S}s of the restore"
    )

    # --- Final read of the group's contents, after the restore-leg positive control: absence by
    # contrast for the users created before subscribing and while the subscription was deleted.
    final = _events(logs, log_group_name, started_ms)
    assert _mentions(final, after_subscription), (
        f"expected the positive-control user {after_subscription!r} to still be present in the log "
        f"group at the end of the run, got {len(final)} events naming none of it"
    )
    assert _mentions(final, resumed), (
        f"expected the post-restore user {resumed!r} to be present in the log group, got "
        f"{len(final)} events naming none of it"
    )
    assert _mentions(final, withheld) == [], (
        f"expected the user created while the subscription was deleted to never be forwarded, not "
        f"even retroactively once forwarding resumed, but {withheld!r} appears in "
        f"{[e.get('message', '')[:120] for e in _mentions(final, withheld)][:3]!r}"
    )
    assert _mentions(final, before_subscription) == [], (
        f"expected the pre-subscription user to never be forwarded, not even retroactively, but "
        f"{before_subscription!r} appears in "
        f"{[e.get('message', '')[:120] for e in _mentions(final, before_subscription)][:3]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
