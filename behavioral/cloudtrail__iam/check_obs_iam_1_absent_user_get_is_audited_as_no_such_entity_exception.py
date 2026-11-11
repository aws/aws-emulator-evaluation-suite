"""obs-iam-1-absent-user-get-is-audited-as-no-such-entity-exception."""

# What AWS writes into the delivered us-east-1 record:
#   * iam:GetUser on a user that does not exist raises SDK error code "NoSuchEntity" (the Smithy
#     model's awsQueryError code), but the CloudTrail record carries errorCode
#     "NoSuchEntityException" -- the Smithy SHAPE name. The two strings differ;
#   * errorMessage is "The user with name <name> cannot be found.", identical to the SDK message;
#   * requestParameters is {"userName": <name>} (populated: the call was not refused by
#     authorization, it was accepted and failed), responseElements is null, readOnly is true;
#   * the GetUser of an EXISTING user carries no errorCode key at all.

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-iam-1-absent-user-get-is-audited-as-no-such-entity-exception"
GROUP = "eventing"
SERVICES = ["cloudtrail", "iam"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# A region LITERAL, legitimately: IAM's events are filed in the partition leader region.
_LEADER_REGION = "us-east-1"
_FALLBACK_COMPARISON_REGION = "us-west-2"

_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

_SDK_CODE = "NoSuchEntity"
_AUDIT_CODE = "NoSuchEntityException"

# ===== helpers =====


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded). Never assert membership in one page."""
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


def _delete_user_if_present(iam, user_name):
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _error_of(fn):
    """(code, message, request_id) of a call that MUST fail. Raises if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""),
                exc.response["ResponseMetadata"]["RequestId"])
    raise AssertionError("the call succeeded; expected it to fail")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """A GetUser for an absent user is audited in us-east-1 with errorCode NoSuchEntityException,
    not the SDK's NoSuchEntity, the SDK's message and the request id; a GetUser of an existing user
    carries no errorCode, and a regional call is filed under its own region.
    """
    iam = ctx.client("iam")

    comparison_region = (
        ctx.region if ctx.region != _LEADER_REGION else _FALLBACK_COMPARISON_REGION
    )
    assert comparison_region != _LEADER_REGION, (
        f"the comparison region resolved to {comparison_region!r}, the leader region itself"
    )
    ct_leader = ctx.client("cloudtrail", region=_LEADER_REGION)
    ct_other = ctx.client("cloudtrail", region=comparison_region)

    absent_user = ctx.unique_name("sim2real-behav-obsiam1abs-")
    present_user = ctx.unique_name("sim2real-behav-obsiam1pre-")
    regional_token = ctx.unique_name("sim2realobsiam1regional").lower()

    iam.create_user(UserName=present_user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_if_present(iam, present_user))

    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()

    # --- The failing read, on a name nobody created.
    sdk_code, sdk_message, sdk_request_id = _error_of(
        lambda: iam.get_user(UserName=absent_user)
    )
    assert sdk_code == _SDK_CODE, (
        f"GetUser on the absent user {absent_user!r} raised {sdk_code!r}, expected {_SDK_CODE!r}: "
        f"{sdk_message!r}"
    )

    # --- The positive control: the same operation on a user that exists.
    got = iam.get_user(UserName=present_user)
    assert got["User"]["UserName"] == present_user, (
        f"GetUser returned {got['User'].get('UserName')!r}, expected {present_user!r}"
    )
    control_request_id = got["ResponseMetadata"]["RequestId"]

    # --- The regional control record.
    ct_other.describe_trails(trailNameList=[regional_token])

    window_start = emitted_at - datetime.timedelta(minutes=2)
    failed_rec = control_rec = regional_rec = None
    polls = 0
    scanned = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        if failed_rec is None or control_rec is None:
            evs = _lookup_all(
                ct_leader, StartTime=window_start, EndTime=window_end, MaxResults=50,
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "GetUser"}],
            )
            scanned += len(evs)
            for ev in evs:
                raw = ev.get("CloudTrailEvent", "")
                if failed_rec is None and absent_user in raw:
                    failed_rec = json.loads(raw)
                elif control_rec is None and control_request_id in raw:
                    control_rec = json.loads(raw)
        if regional_rec is None:
            evs = _lookup_all(
                ct_other, StartTime=window_start, EndTime=window_end, MaxResults=50,
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}],
            )
            for ev in evs:
                raw = ev.get("CloudTrailEvent", "")
                if regional_token in raw:
                    regional_rec = json.loads(raw)
                    break
        if failed_rec is not None and control_rec is not None and regional_rec is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert failed_rec is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail in {_LEADER_REGION} produced no audit record for the "
        f"FAILED iam:GetUser on {absent_user!r} (SDK request id {sdk_request_id}); {polls} polls "
        f"over {waited:.0f}s scanned {scanned} GetUser events. Real AWS indexed it within 140s"
    )
    assert control_rec is not None, (
        f"{DATAPLANE_MARKER}: the SUCCESSFUL control iam:GetUser on {present_user!r} (request id "
        f"{control_request_id}) was never audited after {waited:.0f}s"
    )
    assert regional_rec is not None, (
        f"{DATAPLANE_MARKER}: the regional control DescribeTrails carrying token "
        f"{regional_token!r} was never audited in {comparison_region} after {waited:.0f}s"
    )

    # --- The failure is audited under the SHAPE name, not the wire code.
    assert failed_rec.get("errorCode") == _AUDIT_CODE, (
        f"the audit record for GetUser on an absent user carries errorCode "
        f"{failed_rec.get('errorCode')!r}, expected {_AUDIT_CODE!r}. MEASURED: CloudTrail records "
        f"the exception shape name, while the SDK received {sdk_code!r}; a target that copies the "
        f"wire code into the audit record fails here"
    )
    expected_message = f"The user with name {absent_user} cannot be found."
    assert failed_rec.get("errorMessage") == expected_message, (
        f"errorMessage is {failed_rec.get('errorMessage')!r}, expected {expected_message!r}"
    )
    assert failed_rec["errorMessage"] == sdk_message, (
        f"the audit errorMessage {failed_rec['errorMessage']!r} differs from the SDK's "
        f"{sdk_message!r}"
    )
    assert failed_rec["requestParameters"] == {"userName": absent_user}, (
        f"requestParameters is {failed_rec.get('requestParameters')!r}, expected "
        f"{{'userName': {absent_user!r}}} -- the call was accepted and failed, so unlike an "
        f"authorization refusal its arguments ARE recorded"
    )
    assert failed_rec["responseElements"] is None, (
        f"responseElements is {failed_rec['responseElements']!r} on a failed GetUser"
    )
    assert failed_rec["readOnly"] is True, (
        f"readOnly is {failed_rec.get('readOnly')!r} for GetUser, a read"
    )
    assert failed_rec["eventSource"] == "iam.amazonaws.com", (
        f"eventSource is {failed_rec.get('eventSource')!r}, expected iam.amazonaws.com"
    )
    assert failed_rec["awsRegion"] == _LEADER_REGION, (
        f"awsRegion is {failed_rec.get('awsRegion')!r}, expected {_LEADER_REGION!r}"
    )
    assert failed_rec["requestID"] == sdk_request_id, (
        f"the audit requestID {failed_rec.get('requestID')!r} is not the SDK's request id "
        f"{sdk_request_id!r}"
    )

    # --- Positive control: the same operation succeeding carries no error at all.
    assert "errorCode" not in control_rec, (
        f"the SUCCESSFUL GetUser record carries errorCode {control_rec.get('errorCode')!r}"
    )
    assert "errorMessage" not in control_rec, (
        f"the SUCCESSFUL GetUser record carries errorMessage {control_rec.get('errorMessage')!r}"
    )
    assert control_rec["requestParameters"] == {"userName": present_user}, (
        f"the control's requestParameters is {control_rec.get('requestParameters')!r}, expected "
        f"{{'userName': {present_user!r}}}"
    )

    # --- The regional control is filed under its own region.
    assert regional_rec["awsRegion"] == comparison_region, (
        f"the regional control record carries awsRegion {regional_rec.get('awsRegion')!r}, "
        f"expected {comparison_region!r}"
    )
    assert regional_rec["requestParameters"] == {"trailNameList": [regional_token]}, (
        f"the regional control record carries requestParameters "
        f"{regional_rec.get('requestParameters')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
