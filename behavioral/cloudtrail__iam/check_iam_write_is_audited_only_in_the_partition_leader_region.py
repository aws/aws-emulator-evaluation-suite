"""iam-write-is-audited-only-in-the-partition-leader-region."""

# IAM is a global service: an IAM write made from any region is audited with awsRegion us-east-1
# and LookupEvents returns it in us-east-1 only, while a regional call stays in its own region.
# RoleId and role name are matched as values inside responseElements/requestParameters.

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-write-is-audited-only-in-the-partition-leader-region"
GROUP = "eventing"
SERVICES = ["cloudtrail", "iam"]

# Marks a failure as missing audit behavior rather than a connection or not-implemented error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# A region LITERAL, and legitimately so: IAM is a global service and the aws partition records
# its events in its leader region, us-east-1, whatever region the caller signed in. This is the
# subject of the check, not an environment assumption. The comparison region is derived from
# ctx.region so the check has two distinct regions on every runner.
_LEADER_REGION = "us-east-1"
_FALLBACK_COMPARISON_REGION = "us-west-2"

_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

# ===== helpers =====


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded)."""
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


def _find(events, needle):
    for ev in events:
        if needle in ev.get("CloudTrailEvent", ""):
            return ev
    return None


def _matches(events, needle):
    return [ev for ev in events if needle in ev.get("CloudTrailEvent", "")]


def _delete_role_completely(iam, role_name):
    """Idempotent teardown for exactly the role this check created, never a name-prefix sweep."""
    try:
        names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    for name in names:
        iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    iam.delete_role(RoleName=role_name)


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """An IAM write is audited in us-east-1 and nowhere else, and a regional call is audited in
    its own region and not in us-east-1; the regional call is the twin control for each absence.
    """
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    comparison_region = (
        ctx.region if ctx.region != _LEADER_REGION else _FALLBACK_COMPARISON_REGION
    )
    assert comparison_region != _LEADER_REGION, (
        f"the comparison region resolved to {comparison_region!r}, the same as the leader region; "
        f"the 2x2 needs two distinct regions"
    )
    ct_leader = ctx.client("cloudtrail", region=_LEADER_REGION)
    ct_other = ctx.client("cloudtrail", region=comparison_region)

    role_name = ctx.unique_name("sim2real-behav-ctiamglobal-")
    regional_token = ctx.unique_name("sim2realctiamregional").lower()

    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()

    # --- The global write, and the regional control, in the same instant.
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real-behav CloudTrail global-service-region scenario",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_completely(iam, role_name))
    role_id = created["RoleId"]
    ct_other.describe_trails(trailNameList=[regional_token])

    window_start = emitted_at - datetime.timedelta(minutes=2)
    leader_iam_ev = None
    other_regional_ev = None
    polls = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        if leader_iam_ev is None:
            leader_iam_ev = _find(
                _lookup_all(
                    ct_leader, StartTime=window_start, EndTime=window_end, MaxResults=50,
                    LookupAttributes=[
                        {"AttributeKey": "EventName", "AttributeValue": "CreateRole"}
                    ],
                ),
                role_name,
            )
        if other_regional_ev is None:
            other_regional_ev = _find(
                _lookup_all(
                    ct_other, StartTime=window_start, EndTime=window_end, MaxResults=50,
                    LookupAttributes=[
                        {"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}
                    ],
                ),
                regional_token,
            )
        if leader_iam_ev is not None and other_regional_ev is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert leader_iam_ev is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail in {_LEADER_REGION} produced no audit record for the "
        f"iam:CreateRole this check made. Role {role_name!r} was created at "
        f"{emitted_at.isoformat()} from region {ctx.region!r}; {polls} polls over {waited:.0f}s "
        f"found no CreateRole event naming it in {_LEADER_REGION}. IAM is a global service and "
        f"its events are recorded in the partition leader region; a target that audits nothing, "
        f"or that files IAM events under the caller's region, fails here"
    )
    assert other_regional_ev is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail in {comparison_region} produced no audit record for the "
        f"REGIONAL DescribeTrails control call carrying token {regional_token!r} after {polls} "
        f"polls over {waited:.0f}s. This is the twin control: without it, the assertion below "
        f"that the IAM event is absent from {comparison_region} would be satisfied for free by a "
        f"target whose event history in that region is simply empty"
    )

    iam_record = json.loads(leader_iam_ev["CloudTrailEvent"])
    regional_record = json.loads(other_regional_ev["CloudTrailEvent"])

    # --- The IAM event is stamped with the leader region, not with the caller's.
    assert iam_record["awsRegion"] == _LEADER_REGION, (
        f"the iam:CreateRole record carries awsRegion {iam_record.get('awsRegion')!r}; expected "
        f"{_LEADER_REGION!r}. The call was signed in {ctx.region!r}, and a target that stamps the "
        f"caller's signing region onto a global service's event fails here even when it audits "
        f"the call correctly in every other respect"
    )
    assert iam_record["eventSource"] == "iam.amazonaws.com", (
        f"eventSource is {iam_record.get('eventSource')!r}, expected iam.amazonaws.com"
    )
    assert iam_record["eventName"] == "CreateRole", (
        f"eventName is {iam_record.get('eventName')!r}, expected CreateRole"
    )
    assert iam_record["eventCategory"] == "Management", (
        f"eventCategory is {iam_record.get('eventCategory')!r}, expected Management"
    )
    assert iam_record["readOnly"] is False, (
        f"readOnly is {iam_record.get('readOnly')!r} for CreateRole, which is a write"
    )
    assert iam_record["recipientAccountId"] == account, (
        f"recipientAccountId is {iam_record.get('recipientAccountId')!r}, expected {account!r}"
    )
    assert iam_record["userIdentity"]["arn"] == caller_arn, (
        f"userIdentity.arn is {iam_record['userIdentity'].get('arn')!r}, expected the caller that "
        f"made the write ({caller_arn!r})"
    )
    # Value-level, so the assertion does not depend on the key casing of IAM members.
    request_parameters = iam_record["requestParameters"]
    assert request_parameters is not None, (
        f"requestParameters is null on a SUCCESSFUL iam:CreateRole; real AWS records the "
        f"arguments of an accepted call (it is null only when the call was refused before its "
        f"arguments were accepted). Record: {iam_record.get('eventID')!r}"
    )
    assert role_name in json.dumps(request_parameters), (
        f"requestParameters does not mention the role this check asked to create "
        f"({role_name!r}): {request_parameters!r}. A target that records the operation but "
        f"discards its arguments fails here"
    )
    response_elements = iam_record["responseElements"]
    assert response_elements is not None, (
        "responseElements is null on a SUCCESSFUL iam:CreateRole; the call returned a role, so "
        "there is a response to record. Note the contrast with a DENIED call, where real AWS "
        "records null (measured in "
        "behavioral/cloudtrail/check_lookup_events_records_a_denied_call_with_errorcode_and_"
        "correlates_the_sdk_request_id.py:277)"
    )
    assert role_id in json.dumps(response_elements), (
        f"responseElements does not carry the RoleId CreateRole returned in this run "
        f"({role_id!r}): {response_elements!r}. That id was minted seconds ago, so no recorded "
        f"response can supply it and no template can guess it"
    )

    # --- The regional control's own record, so its presence is not a substring coincidence.
    assert regional_record["awsRegion"] == comparison_region, (
        f"the regional control record carries awsRegion {regional_record.get('awsRegion')!r}, "
        f"expected {comparison_region!r} -- the region the call was actually made in"
    )
    assert regional_record["requestParameters"] == {"trailNameList": [regional_token]}, (
        f"the regional control record carries requestParameters "
        f"{regional_record.get('requestParameters')!r}, expected "
        f"{{'trailNameList': [{regional_token!r}]}}"
    )

    # --- The two absences. A CLOSED window, so both reads are about the same immutable interval
    # in which both events are already demonstrably indexed somewhere.
    absence_end = datetime.datetime.now(datetime.timezone.utc)
    leaked_iam = _matches(
        _lookup_all(
            ct_other, StartTime=window_start, EndTime=absence_end, MaxResults=50,
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "CreateRole"}],
        ),
        role_name,
    )
    assert leaked_iam == [], (
        f"the iam:CreateRole for {role_name!r} is present in {comparison_region!r}'s event "
        f"history as {[ev.get('EventId') for ev in leaked_iam]!r}, as well as in "
        f"{_LEADER_REGION!r} where it belongs. IAM events are recorded in the leader region only, "
        f"so a target serving every region from one flat store double-reports them -- and every "
        f"cross-region deduplication a customer writes against CloudTrail depends on this not "
        f"happening. The comparison region's event history is demonstrably live: the regional "
        f"control {regional_token!r} was found there"
    )
    leaked_regional = _matches(
        _lookup_all(
            ct_leader, StartTime=window_start, EndTime=absence_end, MaxResults=50,
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}
            ],
        ),
        regional_token,
    )
    assert leaked_regional == [], (
        f"the REGIONAL cloudtrail:DescribeTrails made in {comparison_region!r} (token "
        f"{regional_token!r}) is present in {_LEADER_REGION!r}'s event history as "
        f"{[ev.get('EventId') for ev in leaked_regional]!r}. Only global-service events are "
        f"filed in the leader region; a regional call belongs to its own region alone. This is "
        f"the other diagonal, and it is what stops the assertion above from being satisfied by a "
        f"target that replicates everything into every region"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
