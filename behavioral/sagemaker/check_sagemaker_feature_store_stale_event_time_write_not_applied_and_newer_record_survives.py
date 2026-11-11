"""sagemaker-feature-store-stale-event-time-write-not-applied-and-newer-record-survives."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-feature-store-stale-event-time-write-not-applied-and-newer-record-survives"
GROUP = 'overly-permissive'
SERVICES = ['sagemaker']

# Event times are fixed, ordered constants rather than "now" offsets: the whole claim is about the
# ORDER of these four values, so deriving them from the clock would make the check's subject
# depend on how long it took to run. MEASURED: a String EventTime feature must be ISO-8601
# (yyyy-MM-dd'T'HH:mm:ssZ) -- an epoch-seconds string is refused with ValidationError
# "Unable to parse the value provided for the EventTime timestamp".
_T1_OLDEST = "2026-01-01T00:00:00Z"
_T2_STORED = "2026-06-01T00:00:00Z"
_T3_NEWER = "2026-09-01T00:00:00Z"
_T4_DELETE = "2026-09-05T00:00:00Z"

_RID = "R1"
_ABSENT_RID = "R2-never-written"


def _create_feature_store_role(ctx: Any, iam: Any, role_name: str) -> str:
    """The role a feature group is created with. An ONLINE-only store needs no S3 grant at all --
    which is why this check has no bucket and no offline-store residue."""
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "feature-store-event-time"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # IAM propagation exposes no condition to poll, so CreateFeatureGroup's own bounded
    # retry (below) absorbs the delay instead of an unconditional sleep here.
    return arn


def _create_feature_group_with_retry(sm: Any, *, timeout_s: float = 90.0, **kwargs) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.create_feature_group(**kwargs)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            msg = (err.get("Message") or "").lower()
            if err.get("Code") == "ValidationException" \
                    and ("assume" in msg or "not authorized" in msg) \
                    and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _wait_feature_group_created(sm: Any, name: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_feature_group(FeatureGroupName=name)
        if desc["FeatureGroupStatus"] in ("Created", "CreateFailed"):
            return desc
        time.sleep(3)
    raise AssertionError(
        f"feature group {name} never left {desc.get('FeatureGroupStatus')!r} within {timeout_s}s"
    )


def _delete_feature_group(sm: Any, name: str) -> None:
    """Delete and CONFIRM. Deletion is asynchronous and ctx.on_cleanup swallows exceptions, so a
    fire-and-forget delete would leave a feature group that a same-named re-create then conflicts
    with, silently."""
    sm.delete_feature_group(FeatureGroupName=name)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            sm.describe_feature_group(FeatureGroupName=name)
        except ClientError as exc:
            if exc.response["Error"].get("Code") in ("ResourceNotFound", "ValidationException"):
                return
            raise
        time.sleep(5)
    raise AssertionError(f"feature group {name} still exists 300s after DeleteFeatureGroup")


def _record_values(response: dict) -> dict:
    """GetRecord's Record list as a {FeatureName: ValueAsString} mapping, or {} when the store
    returned no record at all.

    An absent record and a present-but-empty one are distinguished by the caller reading
    ``"Record" in response`` -- this helper deliberately does not conflate them.
    """
    return {f["FeatureName"]: f["ValueAsString"] for f in response.get("Record", [])}


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """The online Feature Store is event-time ordered, not last-write-wins: a PutRecord older than
    the stored record (or than a DeleteRecord tombstone) gets an empty 200 and is not applied,
    while a newer PutRecord replaces it (positive control)."""
    sm = ctx.client("sagemaker")
    fsr = ctx.client("sagemaker-featurestore-runtime")
    timeout_s = 300

    role_arn = _create_feature_store_role(
        ctx, iam=ctx.client("iam"), role_name=ctx.unique_name("sim2real-sm-fs-role-")
    )

    group = ctx.unique_name("sim2real-sm-fs-")
    _create_feature_group_with_retry(
        sm,
        FeatureGroupName=group,
        RecordIdentifierFeatureName="rid",
        EventTimeFeatureName="et",
        FeatureDefinitions=[
            {"FeatureName": "rid", "FeatureType": "String"},
            {"FeatureName": "et", "FeatureType": "String"},
            {"FeatureName": "payload", "FeatureType": "String"},
            {"FeatureName": "score", "FeatureType": "Fractional"},
        ],
        OnlineStoreConfig={"EnableOnlineStore": True},
        RoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": "feature-store-event-time"}],
    )
    ctx.on_cleanup(lambda: _delete_feature_group(sm, group))

    described = _wait_feature_group_created(sm, group, timeout_s=timeout_s)
    assert described["FeatureGroupStatus"] == "Created", (
        f"the feature group never became usable: {described.get('FailureReason')!r}"
    )
    assert described["OnlineStoreConfig"]["EnableOnlineStore"] is True, (
        f"the online store must be enabled or nothing below has a data plane: "
        f"{described['OnlineStoreConfig']!r}"
    )
    assert described["EventTimeFeatureName"] == "et", described

    def put(event_time: str, payload: str, score: str) -> dict:
        return fsr.put_record(FeatureGroupName=group, Record=[
            {"FeatureName": "rid", "ValueAsString": _RID},
            {"FeatureName": "et", "ValueAsString": event_time},
            {"FeatureName": "payload", "ValueAsString": payload},
            {"FeatureName": "score", "ValueAsString": score},
        ])

    def get(rid: str = _RID) -> dict:
        return fsr.get_record(FeatureGroupName=group, RecordIdentifierValueAsString=rid)

    # --- Valid setup: a record stored at T2, read back. ---
    put(_T2_STORED, "newer", "2.0")
    stored = get()
    assert _record_values(stored) == {
        "rid": _RID, "et": _T2_STORED, "payload": "newer", "score": "2.0",
    }, f"the store did not round-trip the record it was given: {_record_values(stored)!r}"

    # --- Break exactly one thing: the EventTime moves BACKWARDS. ---
    stale = put(_T1_OLDEST, "stale", "1.0")
    stale_status = stale["ResponseMetadata"]["HTTPStatusCode"]
    assert stale_status == 200, (
        f"real AWS accepts the stale write rather than refusing it; if an emulator refuses, that "
        f"is a divergence worth seeing rather than hiding: HTTP {stale_status}"
    )
    assert [k for k in stale if k != "ResponseMetadata"] == [], (
        f"PutRecord returns an EMPTY body, so the response carries no evidence either way about "
        f"whether the write was applied -- only the following GetRecord does: {stale!r}"
    )

    # Effect absent: every field, including the EventTime, is unchanged.
    after_stale = get()
    assert _record_values(after_stale) == {
        "rid": _RID, "et": _T2_STORED, "payload": "newer", "score": "2.0",
    }, (
        f"a PutRecord with an OLDER EventTime overwrote the stored record -- the online store is "
        f"not event-time ordered: {_record_values(after_stale)!r}, expected the T2 record "
        f"unchanged"
    )

    # --- Positive control, same file: the identical write with a FORWARD EventTime IS applied. ---
    put(_T3_NEWER, "newest", "3.0")
    after_newer = get()
    assert _record_values(after_newer) == {
        "rid": _RID, "et": _T3_NEWER, "payload": "newest", "score": "3.0",
    }, (
        f"positive control: a PutRecord with a NEWER EventTime must replace the record, or the "
        f"assertion above proves only that the store ignores second writes: "
        f"{_record_values(after_newer)!r}"
    )

    # An identifier that was never written is absent, not empty.
    missing = get(_ABSENT_RID)
    assert "Record" not in missing, (
        f"GetRecord for an identifier that was never written must omit Record entirely: "
        f"{ {k: v for k, v in missing.items() if k != 'ResponseMetadata'} !r}"
    )

    batch = fsr.batch_get_record(Identifiers=[{
        "FeatureGroupName": group,
        "RecordIdentifiersValueAsString": [_RID, _ABSENT_RID],
    }])
    returned = {
        r["RecordIdentifierValueAsString"]: {
            f["FeatureName"]: f["ValueAsString"] for f in r["Record"]
        }
        for r in batch["Records"]
    }
    assert list(returned) == [_RID], (
        f"BatchGetRecord must return the one identifier that exists and omit the one that never "
        f"did: {list(returned)!r}"
    )
    assert returned[_RID]["payload"] == "newest", (
        f"BatchGetRecord and GetRecord disagree about the stored record: {returned!r}"
    )
    assert batch["Errors"] == [], (
        f"a never-written identifier is not an error: {batch['Errors']!r}"
    )
    assert batch["UnprocessedIdentifiers"] == [], (
        f"a never-written identifier is not unprocessed either -- real AWS omits it from all "
        f"three lists: {batch['UnprocessedIdentifiers']!r}"
    )

    # --- The same ordering rule, second instance: a delete tombstone is event-timed too. ---
    fsr.delete_record(
        FeatureGroupName=group,
        RecordIdentifierValueAsString=_RID,
        EventTime=_T4_DELETE,
    )
    after_delete = get()
    assert "Record" not in after_delete, (
        f"a deleted record must stop being returned: "
        f"{ {k: v for k, v in after_delete.items() if k != 'ResponseMetadata'} !r}"
    )

    resurrect = put(_T3_NEWER, "resurrected", "9.0")
    assert resurrect["ResponseMetadata"]["HTTPStatusCode"] == 200, resurrect
    after_resurrect = get()
    assert "Record" not in after_resurrect, (
        f"a write at an EventTime OLDER than the delete tombstone must not resurrect the record; "
        f"the store returned "
        f"{_record_values(after_resurrect)!r} -- the delete is ordered against writes by the same "
        f"EventTime rule, not merely a removal that any later write undoes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
