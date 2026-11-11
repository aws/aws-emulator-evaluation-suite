"""cloudtrail-logs-pool-management-but-not-identity-data-events."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "cloudtrail-logs-pool-management-but-not-identity-data-events"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]

#: Ceiling for a management event to appear in event history (observed ~135s).
_INDEX_BUDGET_S = 300.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

#: Operations Cognito logs as data events, therefore absent from event history.
_DATA_EVENT_OPS = (
    "GetId", "GetCredentialsForIdentity", "GetOpenIdToken",
    "GetOpenIdTokenForDeveloperIdentity", "UnlinkIdentity",
)


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded): never assert membership in a single page."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    return out


def _matching(events, needles):
    """Events whose serialised CloudTrailEvent mentions any of *needles*."""
    return [
        ev for ev in events
        if any(n in (ev.get("CloudTrailEvent") or "") for n in needles)
    ]


@tags("axis:negative-delivery", "plane:control", "cap:c2")
def run(ctx) -> None:
    """Event history carries CreateIdentityPool (a management event) but not GetId on the same pool.

    Cognito logs identity-vending operations as data events, which event history does not hold.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html
    """
    ct = ctx.client("cloudtrail")
    ci = ctx.client("cognito-identity")

    account = ctx.client("sts").get_caller_identity()["Account"]

    # The management event is emitted first so the index has the whole check to catch up.
    pool_name = ctx.unique_name("sim2real_behav_ctmark_").replace("-", "_")
    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    # A second management event, issued after GetId: once it is indexed, a GetId record would be too.
    ci.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )

    window_start = emitted_at - datetime.timedelta(minutes=2)

    def _window_end():
        return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)

    def _events_named(name):
        return _lookup_all(
            ct,
            StartTime=window_start,
            EndTime=_window_end(),
            MaxResults=50,
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
        )

    def _await_event(name, needle):
        """The first event-history record named *name* that mentions *needle*, or None at the deadline."""
        budget = _INDEX_BUDGET_S
        left = ctx.time_left()
        if left is not None:
            budget = min(budget, max(0.0, left - 10.0))
        deadline = time.monotonic() + budget
        while True:
            for ev in _events_named(name):
                if needle in (ev.get("CloudTrailEvent") or ""):
                    return ev
            if time.monotonic() >= deadline:
                return None
            time.sleep(_POLL_INTERVAL_S)

    # Positive control: the CreateIdentityPool management event arrives.
    envelope = _await_event("CreateIdentityPool", pool_name)
    latency_s = time.monotonic() - t0
    assert envelope is not None, (
        f"CloudTrail must carry the CreateIdentityPool management event for pool {pool_name!r}; "
        f"after {latency_s:.0f}s of LookupEvents polls no record mentioning it existed. A target "
        f"that audits no identity-pool configuration change at all fails here."
    )
    record = json.loads(envelope["CloudTrailEvent"])

    assert record["eventSource"] == "cognito-identity.amazonaws.com", (
        f"expected eventSource 'cognito-identity.amazonaws.com', got "
        f"{record.get('eventSource')!r}"
    )
    assert record["eventName"] == "CreateIdentityPool", (
        f"expected eventName 'CreateIdentityPool', got {record.get('eventName')!r}"
    )
    assert record["awsRegion"] == ctx.region, (
        f"expected awsRegion {ctx.region!r}, got {record.get('awsRegion')!r}"
    )
    assert record["recipientAccountId"] == account, (
        f"expected recipientAccountId {account!r}, got {record.get('recipientAccountId')!r}"
    )
    assert record["readOnly"] is False, (
        f"CreateIdentityPool mutates, so readOnly must be False, got {record.get('readOnly')!r}"
    )
    assert record["eventCategory"] == "Management", (
        f"CreateIdentityPool is a management event, so eventCategory must be 'Management', got "
        f"{record.get('eventCategory')!r}"
    )
    assert record["requestParameters"]["identityPoolName"] == pool_name, (
        f"the audit record must carry this run's pool name verbatim; expected {pool_name!r}, got "
        f"{record.get('requestParameters', {}).get('identityPoolName')!r}"
    )
    assert envelope["EventName"] == record["eventName"], (
        f"the LookupEvents envelope and the embedded CloudTrailEvent disagree on the operation: "
        f"{envelope.get('EventName')!r} vs {record.get('eventName')!r}"
    )

    needles = (pool_id, identity_id, pool_name)

    def _assert_no_data_event(when):
        hits = _matching(_events_named("GetId"), needles)
        assert not hits, (
            f"{when}: Cognito logs {', '.join(_DATA_EVENT_OPS)} as CloudTrail DATA events, which "
            f"event history does not carry, yet LookupEvents returned {len(hits)} GetId record(s) "
            f"naming this run's pool {pool_id} / identity {identity_id}: "
            f"first={hits[0].get('EventId')!r}"
        )
        # Independent observable: a ResourceName lookup on the pool returns no data-event ops.
        by_resource = _lookup_all(
            ct,
            StartTime=window_start,
            EndTime=_window_end(),
            MaxResults=50,
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": pool_id}
            ],
        )
        data_named = [
            ev for ev in by_resource if ev.get("EventName") in _DATA_EVENT_OPS
        ]
        assert not data_named, (
            f"{when}: a ResourceName lookup on {pool_id} returned data-plane operations "
            f"{[ev.get('EventName') for ev in data_named]}; those are data events and are not "
            f"carried by event history"
        )

    _assert_no_data_event("immediately after the CreateIdentityPool event was delivered")

    # Absence by contrast: the UpdateIdentityPool event issued after GetId is indexed, GetId is not.
    later = _await_event("UpdateIdentityPool", pool_id)
    assert later is not None, (
        f"CloudTrail must carry the UpdateIdentityPool management event for pool {pool_id}; "
        f"after {time.monotonic() - t0:.0f}s of LookupEvents polls no record mentioning it existed"
    )
    _assert_no_data_event("after the UpdateIdentityPool event issued after GetId was delivered")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
