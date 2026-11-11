"""obs-iam-1-read-only-classification-and-response-elements-follow-the-operation."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-iam-1-read-only-classification-and-response-elements-follow-the-operation"
GROUP = "eventing"
SERVICES = ["cloudtrail", "iam"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# A region LITERAL, legitimately: IAM's events are filed in the partition leader region.
_LEADER_REGION = "us-east-1"
_FALLBACK_COMPARISON_REGION = "us-west-2"

_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

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


def _ignore_missing(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


@tags("concern:data-plane", "concern:eventing", "dp:api", "plane:data", "axis:happy-path", "cap:c2")
def run(ctx) -> None:
    """CloudTrail records IAM GetUser and ListRoles as readOnly with null responseElements, and
    CreateRole as not readOnly with responseElements.role naming the minted RoleId, path and ARN.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
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
    account = ctx.client("sts").get_caller_identity()["Account"]

    token = ctx.unique_name("sim2real-behav-obsiam1ro-")
    role_name = token + "-role"
    user_name = token + "-user"
    path = f"/{token}/"
    regional_token = ctx.unique_name("sim2realobsiam1regional").lower()

    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()

    role = iam.create_role(
        RoleName=role_name,
        Path=path,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real-behav CloudTrail readOnly classification scenario",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_role(RoleName=role_name)))
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_user(UserName=user_name)))

    got = iam.get_user(UserName=user_name)
    assert got["User"]["UserName"] == user_name, (
        f"GetUser returned {got['User'].get('UserName')!r}, expected {user_name!r}"
    )
    get_user_request_id = got["ResponseMetadata"]["RequestId"]

    # The path is unique to this run, so "exactly this one role" is a property of the query. IAM
    # list is eventually consistent, so poll the list for the role before taking its record.
    listed = []
    list_request_id = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        listed = []
        for page in iam.get_paginator("list_roles").paginate(PathPrefix=path):
            list_request_id = page["ResponseMetadata"]["RequestId"]
            listed.extend(r["RoleName"] for r in page["Roles"])
        if listed:
            break
        time.sleep(3.0)
    assert listed == [role_name], (
        f"ListRoles under the run-unique path {path!r} returned {listed!r}, expected exactly "
        f"[{role_name!r}] -- the read must have a non-empty response for its null "
        f"responseElements to mean anything"
    )

    # Regional control: this call must be audited in the comparison region.
    ct_other.describe_trails(trailNameList=[regional_token])

    window_start = emitted_at - datetime.timedelta(minutes=2)
    found = {}
    regional_rec = None
    polls = 0
    wanted = {
        "CreateRole": lambda raw: role_name in raw,
        "GetUser": lambda raw: get_user_request_id in raw,
        "ListRoles": lambda raw: list_request_id in raw,
    }
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        for event_name, match in wanted.items():
            if event_name in found:
                continue
            for ev in _lookup_all(
                ct_leader, StartTime=window_start, EndTime=window_end, MaxResults=50,
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
            ):
                raw = ev.get("CloudTrailEvent", "")
                if match(raw):
                    found[event_name] = (ev, json.loads(raw))
                    break
        if regional_rec is None:
            for ev in _lookup_all(
                ct_other, StartTime=window_start, EndTime=window_end, MaxResults=50,
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}],
            ):
                raw = ev.get("CloudTrailEvent", "")
                if regional_token in raw:
                    regional_rec = json.loads(raw)
                    break
        if len(found) == len(wanted) and regional_rec is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    missing = sorted(set(wanted) - set(found))
    assert not missing, (
        f"{DATAPLANE_MARKER}: CloudTrail in {_LEADER_REGION} produced no record for {missing!r} "
        f"after {polls} polls over {waited:.0f}s (role {role_name!r}, user {user_name!r}). Real "
        f"AWS indexed all three within 140s"
    )
    assert regional_rec is not None, (
        f"{DATAPLANE_MARKER}: the regional control DescribeTrails carrying token "
        f"{regional_token!r} was never audited in {comparison_region} after {waited:.0f}s"
    )
    # IAM does not record the response of a read, even a non-empty one; the LookupEvents
    # envelope's ReadOnly member is the string "true"/"false".
    gu_env, gu = found["GetUser"]
    assert gu["readOnly"] is True and gu_env["ReadOnly"] == "true", (
        f"GetUser is recorded readOnly {gu.get('readOnly')!r} (envelope "
        f"{gu_env.get('ReadOnly')!r}); expected True / 'true'"
    )
    assert gu["responseElements"] is None, (
        f"GetUser's responseElements is {gu['responseElements']!r}; MEASURED on real AWS it is "
        f"null even though the API returned the user"
    )
    assert gu["requestParameters"] == {"userName": user_name}, (
        f"GetUser's requestParameters is {gu.get('requestParameters')!r}"
    )
    lr_env, lr = found["ListRoles"]
    assert lr["readOnly"] is True and lr_env["ReadOnly"] == "true", (
        f"ListRoles is recorded readOnly {lr.get('readOnly')!r} (envelope "
        f"{lr_env.get('ReadOnly')!r}); expected True / 'true'"
    )
    assert lr["responseElements"] is None, (
        f"ListRoles' responseElements is {lr['responseElements']!r}; MEASURED on real AWS it is "
        f"null even though the API returned {listed!r}"
    )
    assert lr["requestParameters"] == {"pathPrefix": path}, (
        f"ListRoles' requestParameters is {lr.get('requestParameters')!r}, expected "
        f"{{'pathPrefix': {path!r}}}"
    )

    # A write's response is recorded, with lower-camel member names.
    cr_env, cr = found["CreateRole"]
    assert cr["readOnly"] is False and cr_env["ReadOnly"] == "false", (
        f"CreateRole is recorded readOnly {cr.get('readOnly')!r} (envelope "
        f"{cr_env.get('ReadOnly')!r}); expected False / 'false'"
    )
    recorded_role = (cr.get("responseElements") or {}).get("role")
    assert isinstance(recorded_role, dict), (
        f"CreateRole's responseElements is {cr.get('responseElements')!r}; expected a role object"
    )
    assert recorded_role.get("roleId") == role["RoleId"], (
        f"responseElements.role.roleId is {recorded_role.get('roleId')!r}, expected the RoleId "
        f"CreateRole minted in this run ({role['RoleId']!r})"
    )
    assert recorded_role.get("roleName") == role_name, (
        f"responseElements.role.roleName is {recorded_role.get('roleName')!r}"
    )
    assert recorded_role.get("path") == path, (
        f"responseElements.role.path is {recorded_role.get('path')!r}, expected {path!r}"
    )
    assert recorded_role.get("arn") == role["Arn"], (
        f"responseElements.role.arn is {recorded_role.get('arn')!r}, expected {role['Arn']!r}"
    )
    for name, rec in (("GetUser", gu), ("ListRoles", lr), ("CreateRole", cr)):
        assert "errorCode" not in rec, (
            f"the successful {name} record carries errorCode {rec.get('errorCode')!r}"
        )
        assert rec["awsRegion"] == _LEADER_REGION and rec["eventSource"] == "iam.amazonaws.com", (
            f"{name} record has awsRegion {rec.get('awsRegion')!r}, eventSource "
            f"{rec.get('eventSource')!r}"
        )

    assert regional_rec["awsRegion"] == comparison_region, (
        f"the regional control record carries awsRegion {regional_rec.get('awsRegion')!r}, "
        f"expected {comparison_region!r}"
    )
    assert regional_rec["readOnly"] is True, (
        f"the regional DescribeTrails control is recorded readOnly {regional_rec.get('readOnly')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
