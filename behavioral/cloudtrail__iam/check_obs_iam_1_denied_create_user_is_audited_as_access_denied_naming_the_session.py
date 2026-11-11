"""obs-iam-1-denied-create-user-is-audited-as-access-denied-naming-the-session."""

# What AWS writes into the delivered us-east-1 record:
#   * the SDK raises error code "AccessDenied" for the refused iam:CreateUser, and CloudTrail
#     records errorCode "AccessDenied" -- for IAM the two strings coincide (contrast logs, where
#     the SDK says AccessDeniedException and the audit says AccessDenied);
#   * the audit errorMessage is byte-identical to the SDK error message, and names both
#     "iam:CreateUser" and the assumed-role SESSION ARN
#     arn:aws:sts::<acct>:assumed-role/<role>/<session>;
#   * requestParameters AND responseElements are both null on the refused call;
#   * readOnly is false (the operation is a write, whatever the outcome);
#   * an IAM event is filed under awsRegion us-east-1 whatever region signed the call;
#   * the record is indexed in us-east-1 event history within minutes.

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-iam-1-denied-create-user-is-audited-as-access-denied-naming-the-session"
GROUP = "eventing"
SERVICES = ["cloudtrail", "iam"]

# Marks a failure as missing audit behavior rather than a connection or not-implemented error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# A region LITERAL, legitimately: IAM is a global service whose events the aws partition records
# in its leader region. This is the subject of the check, not an environment assumption.
_LEADER_REGION = "us-east-1"
_FALLBACK_COMPARISON_REGION = "us-west-2"

_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

_SDK_CODE = "AccessDenied"
_AUDIT_CODE = "AccessDenied"

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


def _delete_user_if_present(iam, user_name):
    """Undo a CreateUser a faulty target wrongly accepted. A no-op only when nothing was made."""
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
    raise AssertionError("the call succeeded; expected it to be refused")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c7",
)
def run(ctx) -> None:
    """A CreateUser refused for want of permission is audited in us-east-1 as AccessDenied with the
    SDK's message naming the assumed-role session; the same session's allowed GetRole carries no
    errorCode, and a regional call is filed under its own region.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    ident = sts.get_caller_identity()
    account = ident["Account"]

    comparison_region = (
        ctx.region if ctx.region != _LEADER_REGION else _FALLBACK_COMPARISON_REGION
    )
    assert comparison_region != _LEADER_REGION, (
        f"the comparison region resolved to {comparison_region!r}, the leader region itself"
    )
    ct_leader = ctx.client("cloudtrail", region=_LEADER_REGION)
    ct_other = ctx.client("cloudtrail", region=comparison_region)

    role_name = ctx.unique_name("sim2real-behav-obsiam1den-")
    session_name = "sim2real-obs-iam-1-denied"
    denied_user = ctx.unique_name("sim2real-behav-obsiam1du-")
    regional_token = ctx.unique_name("sim2realobsiam1regional").lower()

    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real-behav CloudTrail denied iam:CreateUser audit scenario",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_completely(iam, role_name))
    # The ONLY grant: iam:GetRole. iam:CreateUser is implicitly denied -- the shape a real caller
    # hits -- and GetRole gives the same session an allowed IAM call to act as positive control.
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-only-get-role",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:GetRole", "Resource": "*"}],
        }),
    )

    # IAM propagation exposes no condition to poll: AssumeRole is retried past AccessDenied.
    creds = None
    last_assume = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role["Arn"], RoleSessionName=session_name)[
                "Credentials"]
            break
        except ClientError as err:
            last_assume = err
            time.sleep(3.0)
    assert creds is not None, (
        f"AssumeRole on the freshly created role {role_name!r} never succeeded within 90s: "
        f"{last_assume!r}"
    )
    limited = ctx.client(
        "iam",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}"

    # --- Positive control first, with the propagation retry at first use of the permission: the
    # same session's ALLOWED iam:GetRole. Its success also proves the session is live, so the
    # refusal below is about iam:CreateUser and not about a session that cannot sign at all.
    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    allowed = None
    last_allowed = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            allowed = limited.get_role(RoleName=role_name)
            break
        except ClientError as err:
            last_allowed = err
            time.sleep(3.0)
    assert allowed is not None, (
        f"the session's ALLOWED iam:GetRole never succeeded within 60s: {last_allowed!r}"
    )
    assert allowed["Role"]["RoleName"] == role_name, (
        f"GetRole returned {allowed['Role'].get('RoleName')!r}, expected {role_name!r}"
    )
    allowed_request_id = allowed["ResponseMetadata"]["RequestId"]

    # --- The refused write. Capture rather than assert-on-success so a faulty target that accepts
    # it still has its user cleaned up.
    ctx.on_cleanup(lambda: _delete_user_if_present(iam, denied_user))
    sdk_code, sdk_message, sdk_request_id = _error_of(
        lambda: limited.create_user(UserName=denied_user)
    )
    assert sdk_code == _SDK_CODE, (
        f"the SDK reported {sdk_code!r} for the refused iam:CreateUser, expected {_SDK_CODE!r}: "
        f"{sdk_message!r}"
    )

    # --- The regional control record, in the same instant.
    ct_other.describe_trails(trailNameList=[regional_token])

    # --- Effect absent: the refused CreateUser created nothing.
    absent_code, _, _ = _error_of(lambda: iam.get_user(UserName=denied_user))
    assert absent_code == "NoSuchEntity", (
        f"GetUser for the user the refused CreateUser named returned {absent_code!r}, expected "
        f"NoSuchEntity -- the refusal must leave no user behind"
    )

    window_start = emitted_at - datetime.timedelta(minutes=2)
    denied_env = denied_rec = None
    allowed_env = allowed_rec = None
    regional_rec = None
    polls = 0
    scanned = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        if denied_rec is None:
            evs = _lookup_all(
                ct_leader, StartTime=window_start, EndTime=window_end, MaxResults=50,
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "CreateUser"}],
            )
            scanned += len(evs)
            for ev in evs:
                raw = ev.get("CloudTrailEvent", "")
                if role_name in raw:
                    denied_env, denied_rec = ev, json.loads(raw)
                    break
        if allowed_rec is None:
            evs = _lookup_all(
                ct_leader, StartTime=window_start, EndTime=window_end, MaxResults=50,
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "GetRole"}],
            )
            scanned += len(evs)
            for ev in evs:
                raw = ev.get("CloudTrailEvent", "")
                if allowed_request_id in raw:
                    allowed_env, allowed_rec = ev, json.loads(raw)
                    break
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
        if denied_rec is not None and allowed_rec is not None and regional_rec is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert denied_rec is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail in {_LEADER_REGION} produced no audit record for the "
        f"iam:CreateUser it REFUSED. Session {session_arn!r} was denied at "
        f"{emitted_at.isoformat()} (SDK request id {sdk_request_id}); {polls} polls over "
        f"{waited:.0f}s scanned {scanned} events and none named role {role_name!r}. Real AWS "
        f"indexed the same refusal within 140s"
    )
    assert allowed_rec is not None, (
        f"{DATAPLANE_MARKER}: the same session's ALLOWED iam:GetRole (request id "
        f"{allowed_request_id}) was never audited in {_LEADER_REGION} after {waited:.0f}s; "
        f"without it the denial assertions cannot be shown to be about the denial"
    )
    assert regional_rec is not None, (
        f"{DATAPLANE_MARKER}: the regional control DescribeTrails carrying token "
        f"{regional_token!r} was never audited in {comparison_region} after {waited:.0f}s"
    )

    # --- The refusal is audited as a refusal.
    assert denied_rec.get("errorCode") == _AUDIT_CODE, (
        f"the audit record for the refused iam:CreateUser carries errorCode "
        f"{denied_rec.get('errorCode')!r}, expected {_AUDIT_CODE!r}"
    )
    message = denied_rec.get("errorMessage") or ""
    assert "iam:CreateUser" in message, (
        f"errorMessage must name the refused action iam:CreateUser; got {message!r}"
    )
    assert session_arn in message, (
        f"errorMessage must name the assumed-role SESSION {session_arn!r}, not the role or the "
        f"base principal; got {message!r}"
    )
    assert message == sdk_message, (
        f"the audit errorMessage {message!r} differs from the message the SDK received "
        f"({sdk_message!r}); MEASURED on real AWS they are byte-identical"
    )
    assert denied_rec["responseElements"] is None, (
        f"responseElements is {denied_rec['responseElements']!r} on a REFUSED call -- there was "
        f"no response to record; a target templating a success shape fails here"
    )
    assert denied_rec["requestParameters"] is None, (
        f"requestParameters is {denied_rec['requestParameters']!r} on a REFUSED call; MEASURED "
        f"on real AWS it is null"
    )
    assert denied_rec["eventSource"] == "iam.amazonaws.com", (
        f"eventSource is {denied_rec.get('eventSource')!r}, expected iam.amazonaws.com"
    )
    assert denied_rec["eventName"] == "CreateUser", (
        f"eventName is {denied_rec.get('eventName')!r}, expected CreateUser"
    )
    assert denied_rec["awsRegion"] == _LEADER_REGION, (
        f"awsRegion is {denied_rec.get('awsRegion')!r}, expected {_LEADER_REGION!r} although "
        f"the call was signed in {ctx.region!r}"
    )
    assert denied_rec["readOnly"] is False, (
        f"readOnly is {denied_rec.get('readOnly')!r} for a refused CreateUser; the "
        f"classification belongs to the operation, which is a write"
    )
    assert denied_rec["requestID"] == sdk_request_id, (
        f"the audit requestID {denied_rec.get('requestID')!r} is not the request id botocore "
        f"observed on the refused call ({sdk_request_id!r})"
    )
    assert denied_rec["userIdentity"]["type"] == "AssumedRole", (
        f"userIdentity.type is {denied_rec['userIdentity'].get('type')!r}, expected AssumedRole"
    )
    assert denied_rec["userIdentity"]["arn"] == session_arn, (
        f"userIdentity.arn is {denied_rec['userIdentity'].get('arn')!r}, expected {session_arn!r}"
    )
    assert denied_env["Resources"] == [], (
        f"the envelope for the refused call reports Resources {denied_env['Resources']!r}; a "
        f"refused call touched nothing"
    )

    # --- Positive control: the same session's allowed call is audited as a success.
    assert "errorCode" not in allowed_rec, (
        f"the ALLOWED iam:GetRole record carries errorCode {allowed_rec.get('errorCode')!r}; the "
        f"denied record's errorCode must not be something this target attaches to everything"
    )
    assert allowed_rec["requestParameters"] == {"roleName": role_name}, (
        f"the allowed GetRole's requestParameters is {allowed_rec.get('requestParameters')!r}, "
        f"expected {{'roleName': {role_name!r}}} -- the contrast with the refused call's null"
    )
    assert allowed_rec["userIdentity"]["arn"] == session_arn, (
        f"the allowed GetRole is attributed to {allowed_rec['userIdentity'].get('arn')!r}, "
        f"expected the same session {session_arn!r}"
    )
    assert allowed_env["Username"] == session_name, (
        f"the allowed call's envelope Username is {allowed_env.get('Username')!r}, expected the "
        f"session name {session_name!r}"
    )

    # --- The regional control is filed under its own region.
    assert regional_rec["awsRegion"] == comparison_region, (
        f"the regional control record carries awsRegion {regional_rec.get('awsRegion')!r}, "
        f"expected {comparison_region!r}"
    )
    assert regional_rec["requestParameters"] == {"trailNameList": [regional_token]}, (
        f"the regional control record carries requestParameters "
        f"{regional_rec.get('requestParameters')!r}, expected "
        f"{{'trailNameList': [{regional_token!r}]}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
