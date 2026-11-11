"""xsvc-cognito-identity-1-vended-session-denied-list-buckets-audited-with-its-federation."""
from __future__ import annotations

import datetime
import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-1-vended-session-denied-list-buckets-audited-with-its-federation"
GROUP = "audit-rejection"
SERVICES = ["cloudtrail", "cognito-identity", "s3"]

COGNITO_SESSION_NAME = "CognitoIdentityCredentials"
COGNITO_PROVIDER = "cognito-identity.amazonaws.com"
_POLICY_NAME = "sim2real-xsvc-grant"
#: Ceiling for the denied AND the allowed ListBuckets records to become findable in event history.
_INDEX_BUDGET_S = 600.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 20
_DENIED_MESSAGE = (
    "User: {session_arn} is not authorized to perform: s3:ListAllMyBuckets because no "
    "identity-based policy allows the s3:ListAllMyBuckets action"
)


# ===== helpers =====

def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet."""
    deadline = time.time() + timeout_s
    last = None
    last_exc = None
    while time.time() < deadline:
        try:
            last = fn()
            if pred(last):
                return last
            last_exc = None
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _set_roles(ci, pool_id, roles, timeout_s=180.0):
    """SetIdentityPoolRoles, retrying only the transient IAM-role-propagation rejections."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)


def _session_client(ctx, service, akid, secret, token):
    """A client signed with temporary credentials, passed explicitly — never via os.environ."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": akid,
            "aws_secret_access_key": secret,
            "aws_session_token": token,
        },
    )


def _client_error(fn, what):
    """Call fn() and return the ClientError it raised; a call that succeeds fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"{what} succeeded, expected a ClientError")


def _events_for_key(ct, access_key_id, start):
    """Every event-history record signed by one access key, paged to exhaustion (bounded)."""
    out = []
    kw = {
        "LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
        "StartTime": start,
        "EndTime": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
        "MaxResults": 50,
    }
    for _ in range(_PAGE_CEILING):
        resp = ct.lookup_events(**kw)
        out.extend(json.loads(ev["CloudTrailEvent"]) for ev in resp.get("Events", []))
        if not resp.get("NextToken"):
            break
        kw["NextToken"] = resp["NextToken"]
    return out
# ===== end helpers =====


@tags("axis:rejection", "dp:api", "plane:data", "cap:c2", "concern:e2e")
def run(ctx) -> None:
    """A Cognito-vended session whose role grants nothing is denied S3 ListBuckets, audited as errorCode
    AccessDenied under its CognitoIdentityCredentials session and federation (pool as aud, identity
    as sub); after a grant, a fresh session's success is audited with no errorCode and the same ARN.
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    ct = ctx.client("cloudtrail")
    account = sts.get_caller_identity()["Account"]
    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)

    developer_provider = "sim2real-xsvc-dev-" + uuid.uuid4().hex[:8]
    pool_name = ctx.unique_name("sim2real_xsvc_ctdeny_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": "xsvc-cognito-identity-1"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": COGNITO_PROVIDER},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {f"{COGNITO_PROVIDER}:aud": pool_id},
                "ForAnyValue:StringLike": {f"{COGNITO_PROVIDER}:amr": "authenticated"},
            },
        }],
    }
    role_name = ctx.unique_name("sim2real-xsvc-ctdeny-auth-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "xsvc-cognito-identity-1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    _set_roles(ci, pool_id, {"authenticated": role_arn})

    user = "sim2real-xsvc-user-" + uuid.uuid4().hex[:12]
    minted = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={developer_provider: user}, TokenDuration=900,
    )
    identity_id, token = minted["IdentityId"], minted["Token"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
    vended = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=identity_id, Logins={COGNITO_PROVIDER: token}),
        lambda r: bool(r.get("Credentials", {}).get("SessionToken")),
        description="GetCredentialsForIdentity to vend authenticated-role credentials",
    )["Credentials"]
    key = vended["AccessKeyId"]
    s3 = _session_client(ctx, "s3", key, vended["SecretKey"], vended["SessionToken"])
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/{COGNITO_SESSION_NAME}"

    # ---- the denial: a role with no permission policy may not list buckets
    err = _client_error(
        lambda: s3.list_buckets(),
        "ListBuckets from a vended session whose role has no permission policy",
    )
    code = err.response.get("Error", {}).get("Code")
    assert code == "AccessDenied", f"expected AccessDenied from ListBuckets, got {code!r}: {err!r}"
    assert err.response["ResponseMetadata"]["HTTPStatusCode"] == 403, (
        f"an S3 AccessDenied is a 403, got {err.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    want_message = _DENIED_MESSAGE.format(session_arn=session_arn)
    message = err.response.get("Error", {}).get("Message")
    assert message == want_message, (
        f"ListBuckets refusal message: expected {want_message!r}, got {message!r}"
    )

    # ---- repair exactly one thing: grant s3:ListAllMyBuckets, and the SAME session gets through
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=_POLICY_NAME,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME))

    # MEASURED on real AWS: the already-vended session stayed on the pre-grant denial
    # for a full 180 s, so a FRESH session is vended for the same identity on every attempt. Nothing
    # here asserts how fast, or whether, a grant reaches a session issued before it.
    granted = {}

    def _attempt():
        fresh = ci.get_credentials_for_identity(
            IdentityId=identity_id, Logins={COGNITO_PROVIDER: token})["Credentials"]
        granted.clear()
        granted.update(fresh)
        client = _session_client(ctx, "s3", fresh["AccessKeyId"], fresh["SecretKey"],
                                 fresh["SessionToken"])
        return client.list_buckets()

    listing = _poll_until(_attempt, lambda r: isinstance(r.get("Buckets"), list),
                          timeout_s=180.0, interval_s=10.0,
                          description="the granted policy to admit a freshly vended session")
    assert listing["Owner"]["ID"], f"a successful ListBuckets names its owner, got {listing!r}"
    granted_key = granted["AccessKeyId"]
    assert granted_key != key, "the post-grant session must be a distinct, freshly vended key"

    # ---- both outcomes are audited, each under its own session's key
    t0 = time.monotonic()
    denied, allowed = [], []
    polls = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        if not denied:
            denied = [r for r in _events_for_key(ct, key, window_start)
                      if r.get("eventName") == "ListBuckets"]
        if not allowed:
            allowed = [r for r in _events_for_key(ct, granted_key, window_start)
                       if r.get("eventName") == "ListBuckets"]
        if denied and allowed:
            break
        time.sleep(_POLL_INTERVAL_S)
    assert denied and allowed, (
        f"event history must carry the denied ListBuckets (key {key}) and the allowed one (key "
        f"{granted_key}) within {_INDEX_BUDGET_S:.0f}s; after {polls} polls found {len(denied)} "
        f"denied and {len(allowed)} allowed"
    )
    assert not any(r.get("errorCode") for r in allowed), (
        f"the post-grant session's ListBuckets succeeded, so its record must carry no errorCode, "
        f"got {[r.get('errorCode') for r in allowed]!r}"
    )

    rec = denied[0]
    assert {r["errorCode"] for r in denied} == {"AccessDenied"}, (
        f"every denied ListBuckets under this key must be audited as AccessDenied, got "
        f"{sorted({r['errorCode'] for r in denied})!r}"
    )
    assert rec["eventSource"] == "s3.amazonaws.com", (
        f"expected eventSource 's3.amazonaws.com', got {rec.get('eventSource')!r}"
    )
    assert rec.get("errorMessage") == want_message, (
        f"the denied record's errorMessage: expected {want_message!r}, got {rec.get('errorMessage')!r}"
    )
    assert not rec.get("responseElements"), (
        f"a refused call produced no response, so responseElements must be empty, got "
        f"{rec.get('responseElements')!r}"
    )
    for label, r, want_key in (("denied", rec, key), ("allowed", allowed[0], granted_key)):
        uid = r["userIdentity"]
        assert uid["type"] == "AssumedRole", f"{label}: expected AssumedRole, got {uid.get('type')!r}"
        assert uid["arn"] == session_arn, (
            f"{label}: the record must be attributed to {session_arn}, got {uid.get('arn')!r}"
        )
        assert uid["accessKeyId"] == want_key, (
            f"{label}: the record must name vended key {want_key}, got {uid.get('accessKeyId')!r}"
        )
        fed = uid["sessionContext"].get("webIdFederationData")
        assert fed and fed.get("federatedProvider") == COGNITO_PROVIDER, (
            f"{label}: webIdFederationData.federatedProvider must be {COGNITO_PROVIDER!r}, got "
            f"{fed!r}"
        )
        attrs = fed.get("attributes") or {}
        assert attrs.get(f"{COGNITO_PROVIDER}:aud") == pool_id, (
            f"{label}: federation aud must be this pool {pool_id}, got {attrs!r}"
        )
        assert attrs.get(f"{COGNITO_PROVIDER}:sub") == identity_id, (
            f"{label}: federation sub must be this identity {identity_id}, got {attrs!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
