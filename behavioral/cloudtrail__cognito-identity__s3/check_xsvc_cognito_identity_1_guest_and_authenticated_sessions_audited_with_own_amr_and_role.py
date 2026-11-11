"""xsvc-cognito-identity-1-guest-and-authenticated-sessions-audited-with-own-amr-and-role."""
from __future__ import annotations

import datetime
import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-1-guest-and-authenticated-sessions-audited-with-own-amr-and-role"
GROUP = "audit-identity"
SERVICES = ["cloudtrail", "cognito-identity", "s3"]

COGNITO_SESSION_NAME = "CognitoIdentityCredentials"
COGNITO_PROVIDER = "cognito-identity.amazonaws.com"
#: Ceiling for BOTH ListBuckets records to become findable in event history.
_INDEX_BUDGET_S = 600.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 20


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


def _create_role(iam, ctx, trust_policy, label, inline_policy):
    """Create a sim2real-xsvc role with one inline policy; teardown registered per create."""
    name = ctx.unique_name(f"sim2real-xsvc-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "xsvc-cognito-identity-1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-xsvc-grant",
                        PolicyDocument=json.dumps(inline_policy))
    # Registered after delete_role so LIFO removes the inline policy first.
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-xsvc-grant"))
    return name, arn


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


def _successful_list_buckets(records):
    return [r for r in records if r.get("eventName") == "ListBuckets" and not r.get("errorCode")]
# ===== end helpers =====


def _amr(record):
    """The amr claim CloudTrail recorded, decoded from its JSON-array string form."""
    raw = (record["userIdentity"]["sessionContext"].get("webIdFederationData") or {}).get(
        "attributes", {}).get(f"{COGNITO_PROVIDER}:amr")
    return json.loads(raw) if isinstance(raw, str) else raw


@tags("axis:happy-path", "dp:api", "plane:data", "cap:c2", "concern:e2e")
def run(ctx) -> None:
    """A guest and a developer-authenticated session from one identity pool each call S3 ListBuckets,
    and CloudTrail audits each under its own pool role, its own amr (unauthenticated vs
    authenticated) and its own identity as sub, with the same provider and aud.
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    ct = ctx.client("cloudtrail")
    account = sts.get_caller_identity()["Account"]
    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)

    developer_provider = "sim2real-xsvc-dev-" + uuid.uuid4().hex[:8]
    pool_name = ctx.unique_name("sim2real_xsvc_ctamr_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": "xsvc-cognito-identity-1"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    list_all = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }

    def _trust(amr):
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": COGNITO_PROVIDER},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {f"{COGNITO_PROVIDER}:aud": pool_id},
                    "ForAnyValue:StringLike": {f"{COGNITO_PROVIDER}:amr": amr},
                },
            }],
        }

    auth_name, auth_arn = _create_role(iam, ctx, _trust("authenticated"), "ctamr-auth", list_all)
    guest_name, guest_arn = _create_role(iam, ctx, _trust("unauthenticated"), "ctamr-guest",
                                         list_all)
    _set_roles(ci, pool_id, {"authenticated": auth_arn, "unauthenticated": guest_arn})

    user = "sim2real-xsvc-user-" + uuid.uuid4().hex[:12]
    minted = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={developer_provider: user}, TokenDuration=900,
    )
    auth_id, token = minted["IdentityId"], minted["Token"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[auth_id]))
    guest_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[guest_id]))
    assert guest_id != auth_id, "a guest GetId must allocate an identity distinct from the developer one"

    sessions = {}
    for label, identity_id, logins in (("auth", auth_id, {COGNITO_PROVIDER: token}),
                                       ("guest", guest_id, None)):
        kw = {"IdentityId": identity_id}
        if logins:
            kw["Logins"] = logins
        creds = _poll_until(lambda: ci.get_credentials_for_identity(**kw),
                            lambda r: bool(r.get("Credentials", {}).get("SessionToken")),
                            description=f"GetCredentialsForIdentity for the {label} identity")["Credentials"]
        client = _session_client(ctx, "s3", creds["AccessKeyId"], creds["SecretKey"],
                                 creds["SessionToken"])
        _poll_until(lambda: client.list_buckets(), lambda r: isinstance(r.get("Buckets"), list),
                    timeout_s=120.0, description=f"ListBuckets under the {label} session")
        sessions[label] = creds["AccessKeyId"]
    assert sessions["auth"] != sessions["guest"], "the two sessions must be distinct credentials"

    t0 = time.monotonic()
    found = {}
    polls = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S and len(found) < 2:
        polls += 1
        for label, key in sessions.items():
            if label not in found:
                hits = _successful_list_buckets(_events_for_key(ct, key, window_start))
                if hits:
                    found[label] = hits[0]
        if len(found) < 2:
            time.sleep(_POLL_INTERVAL_S)
    assert set(found) == {"auth", "guest"}, (
        f"event history must carry a successful ListBuckets for both sessions within "
        f"{_INDEX_BUDGET_S:.0f}s; after {polls} polls only {sorted(found)!r} were found"
    )

    expected = {
        "auth": (auth_name, auth_arn, auth_id),
        "guest": (guest_name, guest_arn, guest_id),
    }
    for label, rec in found.items():
        role_name, role_arn, identity_id = expected[label]
        uid = rec["userIdentity"]
        assert uid["arn"] == f"arn:aws:sts::{account}:assumed-role/{role_name}/{COGNITO_SESSION_NAME}", (
            f"{label}: the session must be audited as {role_name}/{COGNITO_SESSION_NAME}, got "
            f"{uid.get('arn')!r}"
        )
        assert uid["sessionContext"]["sessionIssuer"]["arn"] == role_arn, (
            f"{label}: sessionIssuer must be {role_arn}, got {uid['sessionContext']['sessionIssuer']!r}"
        )
        fed = uid["sessionContext"].get("webIdFederationData") or {}
        assert fed.get("federatedProvider") == COGNITO_PROVIDER, (
            f"{label}: federatedProvider must be {COGNITO_PROVIDER!r}, got {fed!r}"
        )
        attrs = fed.get("attributes") or {}
        assert attrs.get(f"{COGNITO_PROVIDER}:aud") == pool_id, (
            f"{label}: aud must be this pool {pool_id}, got {attrs!r}"
        )
        assert attrs.get(f"{COGNITO_PROVIDER}:sub") == identity_id, (
            f"{label}: sub must be this identity {identity_id}, got {attrs!r}"
        )

    guest_amr = _amr(found["guest"])
    auth_amr = _amr(found["auth"])
    assert guest_amr == ["unauthenticated"], (
        f"a guest session must be audited with amr ['unauthenticated'], got {guest_amr!r}"
    )
    assert "authenticated" in auth_amr and "unauthenticated" not in auth_amr, (
        f"a developer-authenticated session must be audited with amr containing 'authenticated' "
        f"and not 'unauthenticated', got {auth_amr!r}"
    )
    assert any(developer_provider in str(v) for v in auth_amr), (
        f"the authenticated amr must name the developer provider {developer_provider!r}, got "
        f"{auth_amr!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
