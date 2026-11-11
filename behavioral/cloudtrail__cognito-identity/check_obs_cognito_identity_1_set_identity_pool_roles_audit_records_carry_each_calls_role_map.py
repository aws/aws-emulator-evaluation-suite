"""obs-cognito-identity-1-set-identity-pool-roles-audit-records-carry-each-calls-role-map."""
from __future__ import annotations

# Measured on real AWS: SetIdentityPoolRoles is recorded in
# CloudTrail event history as a management event with requestParameters.identityPoolId and
# requestParameters.roles = the role map exactly as sent (e.g. {"authenticated": "<role arn>"}),
# readOnly false, eventCategory "Management", responseElements null, ~92 s after the call. Two
# sequential calls with different maps produced two records, each carrying its own map.
# SetIdentityPoolRoles accepts well-formed role ARNs that name no existing role (it validates the
# ARN, not the role), so this check needs no IAM resources.

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "obs-cognito-identity-1-set-identity-pool-roles-audit-records-carry-each-calls-role-map"
GROUP = "eventing"
SERVICES = ["cloudtrail", "cognito-identity"]

_MARKER_CEILING_S = 600.0
_DEADLINE_MULTIPLE = 4.0
_RECORD_FLOOR_S = 60.0
_RECORD_CEILING_S = 900.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

# ===== helpers =====


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded). Returns (events, pages)."""
    out = []
    nxt = None
    for page in range(1, _PAGE_CEILING + 1):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out, page
    raise AssertionError(
        f"LookupEvents paged past {_PAGE_CEILING} pages without exhausting; refusing to assert "
        "membership in a truncated result"
    )


def _records(ct, event_name, start, predicate):
    events, pages = _lookup_all(
        ct,
        StartTime=start,
        EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
    )
    hits = [r for r in (json.loads(ev["CloudTrailEvent"]) for ev in events) if predicate(r)]
    return hits, pages, len(events)


def _params(raw):
    return raw.get("requestParameters") or {}


# ===== check =====


@tags(
    "axis:happy-path",
    "concern:eventing",
    "concern:representation",
    "cap:c2",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """Each SetIdentityPoolRoles call is audited as a mutating management event whose
    requestParameters.roles is the role map THAT call sent — so two sequential calls leave two
    records with two different maps, not two copies of the pool's final state.
    """
    ct = ctx.client("cloudtrail")
    ci = ctx.client("cognito-identity")
    account = ctx.client("sts").get_caller_identity()["Account"]

    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    pool_name = ctx.unique_name("sim2real_xsvc_ctroles_").replace("-", "_")
    tag = pool_name[-12:]

    t0 = time.monotonic()
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK[:64]},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    def arn(label):
        return f"arn:aws:iam::{account}:role/sim2real-xsvc-ctroles-{label}-{tag}"

    first = {"authenticated": arn("auth1"), "unauthenticated": arn("unauth1")}
    second = {"authenticated": arn("auth2"), "unauthenticated": arn("unauth1")}

    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=first)
    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=second)
    got = ci.get_identity_pool_roles(IdentityPoolId=pool_id).get("Roles", {})
    assert got == second, (
        f"GetIdentityPoolRoles must reflect the LAST write: expected {second!r}, actual {got!r}"
    )

    # ---- calibration: this run's own CreateIdentityPool record ----
    while True:
        hits, pages, n_events = _records(
            ct, "CreateIdentityPool", window_start,
            lambda r: _params(r).get("identityPoolName") == pool_name,
        )
        if hits:
            break
        assert time.monotonic() - t0 < _MARKER_CEILING_S, (
            f"CloudTrail event history never surfaced this run's own CreateIdentityPool for "
            f"{pool_name!r} within {_MARKER_CEILING_S:.0f}s (last scan: {pages} page(s), "
            f"{n_events} events)"
        )
        time.sleep(_POLL_INTERVAL_S)
    marker_latency_s = time.monotonic() - t0
    deadline_s = min(max(_DEADLINE_MULTIPLE * marker_latency_s, _RECORD_FLOOR_S), _RECORD_CEILING_S)

    # ---- both SetIdentityPoolRoles records, pinned to this run's pool ----
    t_wait = time.monotonic()
    polls = 0
    while True:
        polls += 1
        recs, pages, n_events = _records(
            ct, "SetIdentityPoolRoles", window_start,
            lambda r: _params(r).get("identityPoolId") == pool_id,
        )
        maps = [_params(r).get("roles") for r in recs]
        if first in maps and second in maps:
            break
        assert time.monotonic() - t_wait < deadline_s, (
            f"within {deadline_s:.0f}s ({_DEADLINE_MULTIPLE}x the {marker_latency_s:.0f}s marker "
            f"latency) the SetIdentityPoolRoles records for {pool_id!r} carried role maps "
            f"{maps!r}; expected both {first!r} and {second!r} (last scan: {pages} page(s), "
            f"{n_events} events, {polls} polls)"
        )
        time.sleep(_POLL_INTERVAL_S)

    unexpected = [m for m in maps if m not in (first, second)]
    assert not unexpected, (
        f"only two role maps were ever sent to {pool_id!r}, yet records carry {unexpected!r}"
    )
    for rec in recs:
        assert rec.get("eventSource") == "cognito-identity.amazonaws.com", (
            f"eventSource: expected 'cognito-identity.amazonaws.com', actual "
            f"{rec.get('eventSource')!r}"
        )
        assert rec.get("readOnly") is False, (
            f"SetIdentityPoolRoles mutates: readOnly must be False, actual {rec.get('readOnly')!r}"
        )
        assert rec.get("eventCategory") == "Management", (
            f"eventCategory: expected 'Management', actual {rec.get('eventCategory')!r}"
        )
        assert rec.get("errorCode") is None, (
            f"a successful SetIdentityPoolRoles must record no errorCode, actual "
            f"{rec.get('errorCode')!r}"
        )
        assert rec.get("recipientAccountId") == account, (
            f"recipientAccountId: expected {account!r}, actual {rec.get('recipientAccountId')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
