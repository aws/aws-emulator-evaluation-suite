"""obs-iam-1-access-key-secret-and-login-password-are-omitted-from-the-audit-record."""

from __future__ import annotations

import datetime
import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-iam-1-access-key-secret-and-login-password-are-omitted-from-the-audit-record"
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


@tags(
    "concern:data-plane",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
    "axis:happy-path",
    "cap:c2",
)
def run(ctx) -> None:
    """CloudTrail's CreateAccessKey and CreateLoginProfile records omit the secret key and password
    entirely, while the minted key is a working credential (it signs sts:GetCallerIdentity).

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    comparison_region = (
        ctx.region if ctx.region != _LEADER_REGION else _FALLBACK_COMPARISON_REGION
    )
    assert comparison_region != _LEADER_REGION, (
        f"the comparison region resolved to {comparison_region!r}, the leader region itself"
    )
    ct_leader = ctx.client("cloudtrail", region=_LEADER_REGION)
    ct_other = ctx.client("cloudtrail", region=comparison_region)

    user_name = ctx.unique_name("sim2real-behav-obsiam1sec-")
    regional_token = ctx.unique_name("sim2realobsiam1regional").lower()
    # Upper, lower, digit and symbol in the fixed prefix, so any sane password policy is met.
    password = "Sim2r!" + secrets.token_urlsafe(18)

    created_user = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_user(UserName=user_name)))

    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_access_key(
        UserName=user_name, AccessKeyId=key["AccessKeyId"])))
    secret = key["SecretAccessKey"]
    assert secret and len(secret) >= 20, (
        f"CreateAccessKey returned SecretAccessKey {secret!r}; the API response must carry the "
        f"secret, which is what makes its absence from the audit record meaningful"
    )

    profile = iam.create_login_profile(
        UserName=user_name, Password=password, PasswordResetRequired=False
    )["LoginProfile"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_login_profile(UserName=user_name)))
    assert profile["UserName"] == user_name, (
        f"CreateLoginProfile returned UserName {profile.get('UserName')!r}"
    )

    # Regional control: this call must be audited in the comparison region.
    ct_other.describe_trails(trailNameList=[regional_token])

    # New access keys propagate with no pollable condition, so retry the first use.
    keyed_sts = ctx.client(
        "sts",
        creds={"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": secret},
    )
    who = None
    last = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            who = keyed_sts.get_caller_identity()
            break
        except ClientError as err:
            last = err
            time.sleep(3.0)
    assert who is not None, (
        f"the freshly minted access key never signed sts:GetCallerIdentity within 60s: {last!r}"
    )
    assert who["Arn"] == created_user["User"]["Arn"], (
        f"the new key signs as {who['Arn']!r}, expected the user it was minted for "
        f"({created_user['User']['Arn']!r})"
    )

    window_start = emitted_at - datetime.timedelta(minutes=2)
    key_rec = profile_rec = regional_rec = None
    polls = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        for event_name in ("CreateAccessKey", "CreateLoginProfile"):
            if (key_rec if event_name == "CreateAccessKey" else profile_rec) is not None:
                continue
            for ev in _lookup_all(
                ct_leader, StartTime=window_start, EndTime=window_end, MaxResults=50,
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
            ):
                raw = ev.get("CloudTrailEvent", "")
                if user_name in raw:
                    if event_name == "CreateAccessKey":
                        key_rec = json.loads(raw)
                    else:
                        profile_rec = json.loads(raw)
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
        if key_rec is not None and profile_rec is not None and regional_rec is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert key_rec is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail in {_LEADER_REGION} produced no record of the "
        f"iam:CreateAccessKey for {user_name!r} after {polls} polls over {waited:.0f}s. Real AWS "
        f"indexed it within 140s"
    )
    assert profile_rec is not None, (
        f"{DATAPLANE_MARKER}: no record of the iam:CreateLoginProfile for {user_name!r} after "
        f"{waited:.0f}s"
    )
    assert regional_rec is not None, (
        f"{DATAPLANE_MARKER}: the regional control DescribeTrails carrying token "
        f"{regional_token!r} was never audited in {comparison_region} after {waited:.0f}s"
    )

    # The secretAccessKey member is omitted entirely, not replaced by a placeholder.
    access_key = (key_rec.get("responseElements") or {}).get("accessKey")
    assert isinstance(access_key, dict), (
        f"the CreateAccessKey record's responseElements is {key_rec.get('responseElements')!r}; "
        f"expected an accessKey object describing the key that was minted"
    )
    assert access_key.get("accessKeyId") == key["AccessKeyId"], (
        f"responseElements.accessKey.accessKeyId is {access_key.get('accessKeyId')!r}, expected "
        f"the id minted seconds ago ({key['AccessKeyId']!r})"
    )
    assert "secretAccessKey" not in access_key, (
        f"responseElements.accessKey carries secretAccessKey "
        f"{access_key.get('secretAccessKey')!r}. MEASURED on real AWS the member is OMITTED "
        f"entirely from the audit record (not replaced by a placeholder)"
    )
    assert sorted(access_key) == ["accessKeyId", "createDate", "status", "userName"], (
        f"responseElements.accessKey has members {sorted(access_key)!r}; MEASURED on real AWS "
        f"exactly accessKeyId, createDate, status and userName"
    )
    assert access_key["userName"] == user_name and access_key["status"] == "Active", (
        f"responseElements.accessKey is {access_key!r}; expected userName {user_name!r} and "
        f"status 'Active'"
    )
    assert secret not in json.dumps(key_rec), (
        "the CreateAccessKey audit record contains the minted secret access key somewhere in "
        "its serialised form -- a credential leaked into event history"
    )
    assert key_rec["readOnly"] is False and key_rec["eventSource"] == "iam.amazonaws.com", (
        f"CreateAccessKey record has readOnly {key_rec.get('readOnly')!r}, eventSource "
        f"{key_rec.get('eventSource')!r}"
    )

    # The password member is omitted entirely; the other arguments are recorded.
    assert profile_rec["requestParameters"] == {
        "userName": user_name, "passwordResetRequired": False
    }, (
        f"the CreateLoginProfile record's requestParameters is "
        f"{profile_rec.get('requestParameters')!r}; MEASURED on real AWS it is exactly "
        f"{{'userName': {user_name!r}, 'passwordResetRequired': False}} -- the password member "
        f"is OMITTED entirely, not redacted to a placeholder"
    )
    assert password not in json.dumps(profile_rec), (
        "the CreateLoginProfile audit record contains the console password somewhere in its "
        "serialised form -- a credential leaked into event history"
    )
    login = (profile_rec.get("responseElements") or {}).get("loginProfile")
    assert isinstance(login, dict) and login.get("userName") == user_name, (
        f"the CreateLoginProfile record's responseElements is "
        f"{profile_rec.get('responseElements')!r}; expected a loginProfile naming {user_name!r}"
    )
    assert "password" not in login, (
        f"responseElements.loginProfile carries a password member {login.get('password')!r}"
    )
    assert profile_rec["awsRegion"] == _LEADER_REGION, (
        f"awsRegion is {profile_rec.get('awsRegion')!r}, expected {_LEADER_REGION!r}"
    )

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
