"""lookup-events-separates-an-iam-user-identity-from-an-assumed-role-identity."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lookup-events-separates-an-iam-user-identity-from-an-assumed-role-identity"
GROUP = "data-plane"
SERVICES = ["cloudtrail"]

# Marks a detail as a data-plane fidelity failure rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_INDEX_BUDGET_S = 255.0  # LookupEvents indexing lag is typically 80-136 s
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40
_KEY_PROPAGATION_S = 120.0  # a new access key is eventually consistent; retried, not slept
_ASSUME_ROLE_S = 90.0

_SESSION_NAME = "sim2real-behav-ctidentity"


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


def _delete_user_completely(iam, user_name):
    """Idempotent teardown for exactly the user this check created: its keys, its inline
    policies, then the user. Scoped to one name -- never a prefix sweep."""
    try:
        keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    for key in keys:
        iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    for name in iam.list_user_policies(UserName=user_name)["PolicyNames"]:
        iam.delete_user_policy(UserName=user_name, PolicyName=name)
    iam.delete_user(UserName=user_name)


def _delete_role_completely(iam, role_name):
    """Idempotent teardown for exactly the role this check created."""
    try:
        names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    for name in names:
        iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    iam.delete_role(RoleName=role_name)


_DESCRIBE_TRAILS_ONLY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "cloudtrail:DescribeTrails", "Resource": "*"}
    ],
}


def _emit_marker_when_credentials_work(client_factory, token, *, timeout_s, what):
    """Call describe_trails(trailNameList=[token]) with fresh credentials, retrying the codes
    IAM/STS raise while a new principal propagates. Returns the instant it SUCCEEDED; raises on the
    deadline, since an un-emitted marker would make every assertion vacuous."""
    transient = {
        "InvalidClientTokenId", "AccessDenied", "AccessDeniedException",
        "SignatureDoesNotMatch", "UnrecognizedClientException",
    }
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        client = client_factory()
        try:
            client.describe_trails(trailNameList=[token])
            return datetime.datetime.now(datetime.timezone.utc)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in transient:
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(
        f"the {what} could not make a cloudtrail:DescribeTrails call within {timeout_s}s, so "
        f"there is no audit record to inspect. Last error: {last!r}"
    )


def _find(events, token):
    for ev in events:
        if token in ev.get("CloudTrailEvent", ""):
            return ev
    return None


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c7",
)
def run(ctx) -> None:
    """An IAM user's call records userIdentity IAMUser (no sessionContext, its UserId and AKIA key);
    a role session's call records AssumedRole (<RoleId>:<session>, issuer Role, its ASIA key): the
    shape and identifiers follow the credential that signed the request."""
    ct = ctx.client("cloudtrail")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    # --- The IAM user with a long-term key.
    user_name = ctx.unique_name("sim2real-behav-ctident-u-")
    created_user = iam.create_user(
        UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["User"]
    ctx.on_cleanup(lambda: _delete_user_completely(iam, user_name))
    user_id = created_user["UserId"]
    user_arn = created_user["Arn"]
    assert user_arn == f"arn:aws:iam::{account}:user/{user_name}", (
        f"CreateUser returned Arn {user_arn!r}; expected "
        f"arn:aws:iam::{account}:user/{user_name}"
    )
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="sim2real-behav-describe-trails-only",
        PolicyDocument=json.dumps(_DESCRIBE_TRAILS_ONLY),
    )
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    user_access_key_id = key["AccessKeyId"]

    # --- The role, and a session on it.
    role_name = ctx.unique_name("sim2real-behav-ctident-r-")
    created_role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real-behav CloudTrail userIdentity twin-control scenario",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_completely(iam, role_name))
    role_id = created_role["RoleId"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-describe-trails-only",
        PolicyDocument=json.dumps(_DESCRIBE_TRAILS_ONLY),
    )

    # A freshly created role is eventually consistent and exposes no condition to poll, so
    # AssumeRole is a bounded retry that RAISES on expiry rather than a sleep.
    creds = None
    last_assume = None
    deadline = time.monotonic() + _ASSUME_ROLE_S
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=f"arn:aws:iam::{account}:role/{role_name}",
                RoleSessionName=_SESSION_NAME,
            )["Credentials"]
            break
        except ClientError as exc:
            last_assume = exc
            time.sleep(3.0)
    assert creds is not None, (
        f"AssumeRole on the freshly created role {role_name!r} never succeeded within "
        f"{_ASSUME_ROLE_S}s, so the AssumedRole half of the twin control does not exist: "
        f"{last_assume!r}"
    )
    session_access_key_id = creds["AccessKeyId"]

    token_user = ctx.unique_name("sim2realctidentuser").lower()
    token_role = ctx.unique_name("sim2realctidentrole").lower()
    t0 = time.monotonic()
    emitted_user = _emit_marker_when_credentials_work(
        lambda: ctx.client("cloudtrail", creds={
            "aws_access_key_id": user_access_key_id,
            "aws_secret_access_key": key["SecretAccessKey"],
        }),
        token_user, timeout_s=_KEY_PROPAGATION_S, what="IAM user's long-term key",
    )
    emitted_role = _emit_marker_when_credentials_work(
        lambda: ctx.client("cloudtrail", creds={
            "aws_access_key_id": session_access_key_id,
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        }),
        token_role, timeout_s=_ASSUME_ROLE_S, what="assumed-role session",
    )

    window_start = min(emitted_user, emitted_role) - datetime.timedelta(minutes=2)
    user_ev = role_ev = None
    polls = 0
    scanned = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        events = _lookup_all(
            ct,
            StartTime=window_start,
            EndTime=datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=5),
            MaxResults=50,
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}
            ],
        )
        scanned = len(events)
        user_ev = user_ev or _find(events, token_user)
        role_ev = role_ev or _find(events, token_role)
        if user_ev is not None and role_ev is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert user_ev is not None and role_ev is not None, (
        f"{DATAPLANE_MARKER}: event history did not return both halves of the twin control. "
        f"IAM-user marker {token_user!r} found={user_ev is not None}; assumed-role marker "
        f"{token_role!r} found={role_ev is not None}; {polls} polls over {waited:.0f}s scanned "
        f"{scanned} DescribeTrails events. Real AWS indexed markers of this shape in 80-136s."
    )

    user_rec = json.loads(user_ev["CloudTrailEvent"])
    role_rec = json.loads(role_ev["CloudTrailEvent"])
    user_ident = user_rec["userIdentity"]
    role_ident = role_rec["userIdentity"]

    # --- Sanity: each record really is the marker it was located by.
    assert user_rec["requestParameters"] == {"trailNameList": [token_user]}, (
        f"the record located by the IAM-user token carries requestParameters "
        f"{user_rec.get('requestParameters')!r}, expected "
        f"{{'trailNameList': [{token_user!r}]}}"
    )
    assert role_rec["requestParameters"] == {"trailNameList": [token_role]}, (
        f"the record located by the role token carries requestParameters "
        f"{role_rec.get('requestParameters')!r}, expected "
        f"{{'trailNameList': [{token_role!r}]}}"
    )

    # --- The IAM user branch.
    assert user_ident["type"] == "IAMUser", (
        f"a call signed with an IAM user's long-term access key was audited with "
        f"userIdentity.type={user_ident.get('type')!r}, expected 'IAMUser'. The type is a "
        f"function of the CREDENTIAL, not a constant"
    )
    assert user_ident["userName"] == user_name, (
        f"userIdentity.userName is {user_ident.get('userName')!r}, expected the user this check "
        f"created ({user_name!r})"
    )
    assert user_ident["principalId"] == user_id, (
        f"userIdentity.principalId is {user_ident.get('principalId')!r}, expected the UserId "
        f"CreateUser returned in this run ({user_id!r}). This value did not exist a minute ago, "
        f"so no recorded response can carry it"
    )
    assert user_ident["arn"] == user_arn, (
        f"userIdentity.arn is {user_ident.get('arn')!r}, expected {user_arn!r}"
    )
    assert user_ident["accountId"] == account, (
        f"userIdentity.accountId is {user_ident.get('accountId')!r}, expected {account!r}"
    )
    assert user_ident["accessKeyId"] == user_access_key_id, (
        f"userIdentity.accessKeyId is {user_ident.get('accessKeyId')!r}, expected the full key "
        f"id CreateAccessKey returned in this run ({user_access_key_id!r}) -- not a truncated, "
        f"masked or synthesised form"
    )
    assert "sessionContext" not in user_ident, (
        f"userIdentity for a LONG-TERM-key call carries sessionContext "
        f"{user_ident.get('sessionContext')!r}; the member exists only for temporary session "
        f"credentials, and a target that attaches it unconditionally fails here. Members "
        f"present: {sorted(user_ident)!r}"
    )
    assert user_ev["Username"] == user_name, (
        f"the envelope's Username is {user_ev.get('Username')!r} for an IAM-user call, expected "
        f"the user's name {user_name!r}"
    )

    # --- The assumed-role branch.
    assert role_ident["type"] == "AssumedRole", (
        f"a call signed with role session credentials was audited with "
        f"userIdentity.type={role_ident.get('type')!r}, expected 'AssumedRole'"
    )
    assert role_ident["principalId"] == f"{role_id}:{_SESSION_NAME}", (
        f"userIdentity.principalId is {role_ident.get('principalId')!r}, expected "
        f"'<RoleId>:<RoleSessionName>' = {role_id + ':' + _SESSION_NAME!r} built from the RoleId "
        f"CreateRole returned in this run"
    )
    assert role_ident["arn"] == (
        f"arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME}"
    ), (
        f"userIdentity.arn is {role_ident.get('arn')!r}, expected the assumed-role session ARN "
        f"arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME} -- note it is an "
        f"arn:aws:sts ARN, not the arn:aws:iam role ARN"
    )
    assert role_ident["accessKeyId"] == session_access_key_id, (
        f"userIdentity.accessKeyId is {role_ident.get('accessKeyId')!r}, expected the session "
        f"key id AssumeRole returned in this run ({session_access_key_id!r})"
    )
    session_issuer = role_ident["sessionContext"]["sessionIssuer"]
    assert session_issuer["type"] == "Role", (
        f"sessionContext.sessionIssuer.type is {session_issuer.get('type')!r}, expected 'Role'"
    )
    assert session_issuer["userName"] == role_name, (
        f"sessionContext.sessionIssuer.userName is {session_issuer.get('userName')!r}, expected "
        f"the role this check created ({role_name!r})"
    )
    assert session_issuer["principalId"] == role_id, (
        f"sessionContext.sessionIssuer.principalId is {session_issuer.get('principalId')!r}, "
        f"expected the bare RoleId {role_id!r} -- the ISSUER's id carries no session suffix, "
        f"unlike userIdentity.principalId above"
    )
    assert session_issuer["arn"] == f"arn:aws:iam::{account}:role/{role_name}", (
        f"sessionContext.sessionIssuer.arn is {session_issuer.get('arn')!r}, expected "
        f"arn:aws:iam::{account}:role/{role_name}"
    )
    assert role_ev["Username"] == _SESSION_NAME, (
        f"the envelope's Username is {role_ev.get('Username')!r} for an assumed-role call, "
        f"expected the role SESSION name {_SESSION_NAME!r}"
    )

    # --- The two shapes are genuinely different, which is what a templating target gets wrong.
    assert user_ident["type"] != role_ident["type"], (
        f"both records carry userIdentity.type={user_ident['type']!r}. Two different credential "
        f"kinds made the same call in the same second; a target that emits one templated "
        f"identity for everything lands here"
    )
    assert user_ident["accessKeyId"] != role_ident["accessKeyId"], (
        f"both records report the same accessKeyId {user_ident['accessKeyId']!r}, but the calls "
        f"were signed with {user_access_key_id!r} and {session_access_key_id!r}"
    )
    assert user_ident["principalId"] != role_ident["principalId"], (
        f"both records report principalId {user_ident['principalId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
