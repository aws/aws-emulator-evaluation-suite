"""obs-cognito-idp-3-failed-and-denied-admin-get-user-calls-are-audited-with-their-error-code."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cognito-idp-3-failed-and-denied-admin-get-user-calls-are-audited-with-their-error-code"
GROUP = "eventing"
SERVICES = ["cloudtrail", "cognito-idp"]

# Marks a data-plane failure so it reads as a fidelity failure rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_SOURCE = "cognito-idp.amazonaws.com"
_EVENT = "AdminGetUser"

# LookupEvents indexes management events about 50-140 s after the call; 255 s leaves headroom.
_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40
# A new role's trust policy is not usable at once: AssumeRole answers AccessDenied for some seconds.
_PROPAGATION_BUDGET_S = 60.0

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


def _error_of(fn):
    """(code, message, request_id) of a call that must fail. Raises on unexpected success --
    never returns a falsy sentinel, so an over-permissive target fails loudly here."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        rid = exc.response.get("ResponseMetadata", {}).get("RequestId")
        return err.get("Code"), err.get("Message"), rid
    raise AssertionError(
        f"the call SUCCEEDED where real AWS refuses it; response keys {sorted(resp)!r}. An "
        f"over-permissive target must not reach the audit assertions below"
    )


def _delete_user_pool(idp, pool_id):
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_role_completely(iam, role_name):
    try:
        names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    for name in names:
        iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    iam.delete_role(RoleName=role_name)


def _assume_with_retry(sts, role_arn, session_name):
    """IAM exposes no condition to poll for trust-policy propagation, so the bounded AccessDenied
    retry at first use IS the wait."""
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    caller_arn = sts.get_caller_identity()["Arn"]
    not_yet = f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}"
    while True:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            if last != "AccessDenied" or message != not_yet or time.monotonic() >= deadline:
                raise AssertionError(
                    f"AssumeRole on {role_arn} did not become usable within "
                    f"{_PROPAGATION_BUDGET_S:.0f}s: expected success, actual code {last!r} ({message!r})"
                ) from exc
            time.sleep(3.0)


def _describe_with_retry(idp, pool_id, session_arn, pool_arn):
    """The role's one granted action. Retried on its not-yet-granted AccessDeniedException only,
    because the inline policy granting it propagates like the trust policy does."""
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    not_yet = (
        f"User: {session_arn} is not authorized to perform: cognito-idp:DescribeUserPool on resource: "
        f"{pool_arn} because no identity-based policy allows the cognito-idp:DescribeUserPool action"
    )
    while True:
        try:
            return idp.describe_user_pool(UserPoolId=pool_id)
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            if last != "AccessDeniedException" or message != not_yet or time.monotonic() >= deadline:
                raise AssertionError(
                    f"the role's GRANTED cognito-idp:DescribeUserPool on {pool_id!r} never "
                    f"succeeded within {_PROPAGATION_BUDGET_S:.0f}s: actual code {last!r} ({message!r}). "
                    f"Without this positive control the AdminGetUser denial below proves nothing"
                ) from exc
            time.sleep(3.0)


@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c7",
)
def run(ctx) -> None:
    """A failed (unknown user) and a denied (no grant) AdminGetUser call each appear in LookupEvents with
    their own error code, joined to the exact request by requestID, beside a successful control call."""
    ct = ctx.client("cloudtrail")
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()
    account = caller["Account"]
    caller_arn = caller["Arn"]

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-ctidp3-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_user_pool(idp, pool_id))

    user_name = ctx.unique_name("sim2realctidp3user")
    ghost_name = ctx.unique_name("sim2realctidp3ghost")
    idp.admin_create_user(UserPoolId=pool_id, Username=user_name, MessageAction="SUPPRESS")

    # The denied caller: a role granted ONLY DescribeUserPool on cognito-idp.
    role_name = ctx.unique_name("sim2real-behav-ctidp3-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:256]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_completely(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="simparity-inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "cognito-idp:DescribeUserPool",
                "Resource": "*",
            }],
        }),
    )

    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()

    # --- CONTROL: an existing user.
    ok = idp.admin_get_user(UserPoolId=pool_id, Username=user_name)
    assert ok.get("Username") == user_name, (
        f"AdminGetUser for the user this check just created returned Username "
        f"{ok.get('Username')!r}, expected {user_name!r}"
    )
    user_sub = next(
        (a["Value"] for a in ok.get("UserAttributes", []) if a.get("Name") == "sub"), None
    )
    assert user_sub, f"AdminGetUser returned no sub attribute: {ok.get('UserAttributes')!r}"
    ok_request_id = ok["ResponseMetadata"]["RequestId"]

    # --- FAILED: a username that does not exist in the pool.
    nf_code, nf_message, nf_request_id = _error_of(
        lambda: idp.admin_get_user(UserPoolId=pool_id, Username=ghost_name)
    )
    assert nf_code == "UserNotFoundException", (
        f"AdminGetUser for a nonexistent username returned code {nf_code!r} "
        f"(message {nf_message!r}), expected 'UserNotFoundException'"
    )
    assert nf_message == "User does not exist.", (
        f"unexpected UserNotFoundException message: {nf_message!r}"
    )

    # --- DENIED: a session with no cognito-idp:AdminGetUser grant.
    session = _assume_with_retry(sts, role_arn, ctx.unique_name("ctidp3")[:64])
    c = session["Credentials"]
    role_idp = ctx.client("cognito-idp", creds={
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    })
    session_arn = session["AssumedRoleUser"]["Arn"]
    pool_arn = f"arn:aws:cognito-idp:{ctx.region}:{account}:userpool/{pool_id}"
    described = _describe_with_retry(role_idp, pool_id, session_arn, pool_arn)
    assert described["UserPool"]["Id"] == pool_id, (
        f"the role's granted DescribeUserPool returned pool {described['UserPool'].get('Id')!r}, "
        f"expected {pool_id!r}"
    )
    dn_code, dn_message, dn_request_id = _error_of(
        lambda: role_idp.admin_get_user(UserPoolId=pool_id, Username=user_name)
    )
    assert dn_code == "AccessDeniedException", (
        f"AdminGetUser from a session granted only DescribeUserPool returned code {dn_code!r} "
        f"(message {dn_message!r}), expected 'AccessDeniedException'"
    )
    assert dn_message == (
        f"User: {session_arn} is not authorized to perform: cognito-idp:AdminGetUser on "
        f"resource: arn:aws:cognito-idp:{ctx.region}:{account}:userpool/{pool_id} because no "
        f"identity-based policy allows the cognito-idp:AdminGetUser action"
    ), f"unexpected denial message: {dn_message!r}"

    wanted = {ok_request_id: "control", nf_request_id: "failed", dn_request_id: "denied"}
    assert len(wanted) == 3 and all(wanted), (
        f"the three calls did not yield three distinct request ids: {wanted!r}"
    )

    # --- Poll CloudTrail for the three records, joined by requestID.
    window_start = emitted_at - datetime.timedelta(minutes=3)
    found: dict[str, dict] = {}
    polls = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        events = _lookup_all(
            ct, StartTime=window_start, EndTime=window_end, MaxResults=50,
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": _EVENT}],
        )
        for ev in events:
            raw = ev.get("CloudTrailEvent", "")
            if not any(rid in raw for rid in wanted):
                continue
            record = json.loads(raw)
            role = wanted.get(record.get("requestID"))
            if role:
                found[role] = record
        if len(found) == 3:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    missing = sorted(set(wanted.values()) - set(found))
    assert not missing, (
        f"{DATAPLANE_MARKER}: CloudTrail produced no AdminGetUser record for the {missing!r} "
        f"call(s) on pool {pool_id!r} after {polls} polls over {waited:.0f}s (found "
        f"{sorted(found)!r}; request ids {wanted!r}). Real AWS indexed all three in ~50 s. A "
        f"target that audits only successful calls blinds every failed-access alarm"
    )

    for role, record in found.items():
        assert record.get("eventSource") == _SOURCE, (
            f"the {role} record's eventSource is {record.get('eventSource')!r}, expected {_SOURCE!r}"
        )
        assert record.get("eventName") == _EVENT, (
            f"the {role} record's eventName is {record.get('eventName')!r}, expected {_EVENT!r}"
        )
        assert record.get("readOnly") is True, (
            f"the {role} record's readOnly is {record.get('readOnly')!r}; AdminGetUser is a read, "
            f"and it stays one whether or not it succeeded"
        )
        assert record.get("recipientAccountId") == account, (
            f"the {role} record's recipientAccountId is {record.get('recipientAccountId')!r}, "
            f"expected {account!r}"
        )

    # --- CONTROL record.
    control = found["control"]
    assert "errorCode" not in control and "errorMessage" not in control, (
        f"the successful AdminGetUser's record carries errorCode {control.get('errorCode')!r} / "
        f"errorMessage {control.get('errorMessage')!r}; a success has neither"
    )
    assert (control.get("requestParameters") or {}).get("userPoolId") == pool_id, (
        f"the control record's requestParameters are {control.get('requestParameters')!r}, "
        f"expected userPoolId {pool_id!r}"
    )
    assert (control.get("additionalEventData") or {}).get("sub") == user_sub, (
        f"the control record's additionalEventData is {control.get('additionalEventData')!r}, "
        f"expected sub {user_sub!r} -- the user AdminGetUser returned"
    )
    assert (control.get("userIdentity") or {}).get("arn") == caller_arn, (
        f"the control record's userIdentity arn is "
        f"{(control.get('userIdentity') or {}).get('arn')!r}, expected the caller {caller_arn!r}"
    )

    # --- FAILED record: the service's own error, kept verbatim.
    failed = found["failed"]
    assert failed.get("errorCode") == "UserNotFoundException", (
        f"the failed AdminGetUser's record has errorCode {failed.get('errorCode')!r}, expected "
        f"'UserNotFoundException' -- the code the caller received"
    )
    assert failed.get("errorMessage") == nf_message, (
        f"the failed record's errorMessage is {failed.get('errorMessage')!r}, expected the message "
        f"the caller received ({nf_message!r})"
    )
    assert (failed.get("requestParameters") or {}).get("userPoolId") == pool_id, (
        f"the failed record's requestParameters are {failed.get('requestParameters')!r}, expected "
        f"userPoolId {pool_id!r}: the service refused the call, but it saw the arguments"
    )
    assert failed.get("responseElements") is None, (
        f"the failed record carries responseElements {failed.get('responseElements')!r}; a "
        f"refused call returned nothing"
    )
    assert "sub" not in (failed.get("additionalEventData") or {}), (
        f"the failed record names a user sub {failed.get('additionalEventData')!r}, but no user "
        f"was found"
    )

    # --- DENIED record: IAM's refusal, under its own code and the session's identity.
    denied = found["denied"]
    assert denied.get("errorCode") == "AccessDenied", (
        f"the denied AdminGetUser's record has errorCode {denied.get('errorCode')!r}, expected "
        f"'AccessDenied'. The caller received {dn_code!r}; CloudTrail records an IAM denial under "
        f"its own code, not the API exception name"
    )
    assert denied.get("errorMessage") == dn_message, (
        f"the denied record's errorMessage is {denied.get('errorMessage')!r}, expected the message "
        f"the caller received ({dn_message!r})"
    )
    assert denied.get("requestParameters") is None, (
        f"the denied record carries requestParameters {denied.get('requestParameters')!r}; real "
        f"AWS records null, because IAM refused the call before the service read its arguments"
    )
    identity = denied.get("userIdentity") or {}
    assert identity.get("type") == "AssumedRole" and identity.get("arn") == session_arn, (
        f"the denied record's userIdentity is type {identity.get('type')!r} arn "
        f"{identity.get('arn')!r}, expected AssumedRole {session_arn!r} -- the session that was "
        f"refused, not the principal that created it"
    )
    issuer = ((identity.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
    assert issuer == role_arn, (
        f"the denied record's sessionIssuer arn is {issuer!r}, expected the role {role_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
