"""obs-cognito-identity-1-describe-missing-pool-is-rejected-and-audited-with-its-error."""
from __future__ import annotations

# Measured on real AWS: DescribeIdentityPool on a well-formed but nonexistent "<region>:<uuid>" id
# returns ResourceNotFoundException (HTTP 400), and CloudTrail event history carries the refused
# call as a management event with errorCode "ResourceNotFoundException", errorMessage "IdentityPool
# '<id>' not found.", requestParameters.identityPoolId = the id asked for, responseElements null,
# readOnly true and eventCategory "Management" — surfaced ~87 s after the call. A SUCCESSFUL
# DescribeIdentityPool is also recorded with responseElements null (CloudTrail does not log this
# read's response), so the null responseElements alone does not separate the two; the errorCode
# does.

import datetime
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cognito-identity-1-describe-missing-pool-is-rejected-and-audited-with-its-error"
GROUP = "eventing"
SERVICES = ["cloudtrail", "cognito-identity"]

#: Ceiling for this run's own CreateIdentityPool record (the calibration marker) to surface.
_MARKER_CEILING_S = 600.0
#: The Describe records then get 4x the marker's measured latency, clamped.
_DEADLINE_MULTIPLE = 4.0
_RECORD_FLOOR_S = 60.0
_RECORD_CEILING_S = 900.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

_NOT_FOUND = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "IdentityPool '{pool_id}' not found."

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


def _error(fn):
    """(code, message) of the AWS error `fn` raised. An unexpected SUCCESS raises, never returns a
    falsy code."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be refused, but it SUCCEEDED and returned keys {sorted(resp)!r}"
    )


def _assert_refused_record(rec, region, message):
    """Every record naming the missing id is the refused read, fully classified."""
    assert rec.get("eventSource") == "cognito-identity.amazonaws.com", (
        f"eventSource: expected 'cognito-identity.amazonaws.com', actual {rec.get('eventSource')!r}"
    )
    assert rec.get("errorCode") == _NOT_FOUND, (
        f"the refused read's record must carry errorCode {_NOT_FOUND!r}, actual "
        f"{rec.get('errorCode')!r}"
    )
    assert rec.get("errorMessage") == message, (
        f"the refused read's record errorMessage: expected {message!r}, actual "
        f"{rec.get('errorMessage')!r}"
    )
    assert rec.get("responseElements") is None, (
        f"a refused call returned nothing, so responseElements must be absent/null, actual "
        f"{rec.get('responseElements')!r}"
    )
    assert rec.get("readOnly") is True, (
        f"DescribeIdentityPool is a read: readOnly must be True even when refused, actual "
        f"{rec.get('readOnly')!r}"
    )
    assert rec.get("eventCategory") == "Management", (
        f"eventCategory: expected 'Management', actual {rec.get('eventCategory')!r}"
    )
    assert rec.get("awsRegion") == region, (
        f"awsRegion: expected {region!r}, actual {rec.get('awsRegion')!r}"
    )


# ===== check =====


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:eventing",
    "cap:c2",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A DescribeIdentityPool on a well-formed id that names no pool is refused with
    ResourceNotFoundException and audited as a read-only management event with errorCode and
    errorMessage, while the same operation on a pool that exists is audited with no errorCode.
    """
    ct = ctx.client("cloudtrail")
    ci = ctx.client("cognito-identity")

    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    pool_name = ctx.unique_name("sim2real_xsvc_ctdesc_").replace("-", "_")

    t0 = time.monotonic()
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        IdentityPoolTags={"sim2real": CHECK[:64]},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    # Positive control: the real pool describes.
    described = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolName"] == pool_name, (
        f"DescribeIdentityPool on the pool just created returned name "
        f"{described.get('IdentityPoolName')!r}, expected {pool_name!r}"
    )

    # The negative: same region prefix, same shape, a uuid no pool can own.
    missing_id = f"{ctx.region}:{uuid.uuid4()}"
    code, message = _error(lambda: ci.describe_identity_pool(IdentityPoolId=missing_id))
    assert code == _NOT_FOUND, (
        f"DescribeIdentityPool on nonexistent {missing_id!r}: expected {_NOT_FOUND!r}, actual {code!r}"
    )
    want_message = _NOT_FOUND_MESSAGE.format(pool_id=missing_id)
    assert message == want_message, (
        f"DescribeIdentityPool on nonexistent {missing_id!r}: expected message {want_message!r}, "
        f"actual {message!r}"
    )
    # Effect absent, and the refusal did not disturb the real pool.
    assert ci.describe_identity_pool(IdentityPoolId=pool_id)["IdentityPoolId"] == pool_id, (
        "the real pool must still describe after the refused read"
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

    # ---- both DescribeIdentityPool records, each pinned by the id it asked for ----
    t_wait = time.monotonic()
    polls = 0
    while True:
        polls += 1
        recs, pages, n_events = _records(
            ct, "DescribeIdentityPool", window_start,
            lambda r: _params(r).get("identityPoolId") in (pool_id, missing_id),
        )
        refused = [r for r in recs if _params(r).get("identityPoolId") == missing_id]
        served = [r for r in recs if _params(r).get("identityPoolId") == pool_id]
        if refused and len(served) >= 2:
            break
        assert time.monotonic() - t_wait < deadline_s, (
            f"within {deadline_s:.0f}s ({_DEADLINE_MULTIPLE}x the {marker_latency_s:.0f}s marker "
            f"latency) event history held {len(refused)} DescribeIdentityPool record(s) for the "
            f"missing id {missing_id!r} and {len(served)} for the real pool; expected >=1 and >=2 "
            f"(last scan: {pages} page(s), {n_events} events, {polls} polls)"
        )
        time.sleep(_POLL_INTERVAL_S)

    for rec in refused:
        _assert_refused_record(rec, ctx.region, want_message)

    # Positive control at the trail: the served reads carry no error fields at all.
    for ok in served:
        assert ok.get("errorCode") is None and ok.get("errorMessage") is None, (
            f"a SUCCESSFUL DescribeIdentityPool on {pool_id!r} must record no error, actual "
            f"errorCode={ok.get('errorCode')!r} errorMessage={ok.get('errorMessage')!r}"
        )
        assert ok.get("readOnly") is True, (
            f"successful DescribeIdentityPool readOnly: expected True, actual {ok.get('readOnly')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
