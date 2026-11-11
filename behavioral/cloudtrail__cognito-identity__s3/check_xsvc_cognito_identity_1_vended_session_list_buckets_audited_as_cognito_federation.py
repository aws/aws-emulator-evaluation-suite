"""xsvc-cognito-identity-1-vended-session-list-buckets-audited-as-cognito-federation."""
from __future__ import annotations

import datetime
import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-1-vended-session-list-buckets-audited-as-cognito-federation"
GROUP = "audit-identity"
SERVICES = ["cloudtrail", "cognito-identity", "s3"]

COGNITO_SESSION_NAME = "CognitoIdentityCredentials"
COGNITO_PROVIDER = "cognito-identity.amazonaws.com"
#: Ceiling for BOTH ListBuckets records to become findable in event history. The CreateIdentityPool
#: sibling in behavioral/cognito-identity measured ~135 s for a management event to index.
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


@tags("axis:happy-path", "dp:api", "plane:data", "cap:c2", "cap:c7", "concern:e2e")
def run(ctx) -> None:
    """S3 ListBuckets with Cognito-vended credentials is audited as an AssumedRole session whose
    webIdFederationData names cognito-identity.amazonaws.com with this pool as aud and identity as
    sub, while the same call from a plain sts:AssumeRole session carries no federation data.
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    ct = ctx.client("cloudtrail")
    account = sts.get_caller_identity()["Account"]
    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)

    developer_provider = "sim2real-xsvc-dev-" + uuid.uuid4().hex[:8]
    pool_name = ctx.unique_name("sim2real_xsvc_ctfed_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": "xsvc-cognito-identity-1"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    list_all = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }
    cognito_trust = {
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
    auth_name, auth_arn = _create_role(iam, ctx, cognito_trust, "ctfed-auth", list_all)
    plain_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    plain_name, plain_arn = _create_role(iam, ctx, plain_trust, "ctfed-plain", list_all)
    _set_roles(ci, pool_id, {"authenticated": auth_arn})

    # ---- the Cognito-vended session, via a developer-authenticated identity
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
    cognito_key = vended["AccessKeyId"]
    cognito_s3 = _session_client(ctx, "s3", cognito_key, vended["SecretKey"],
                                 vended["SessionToken"])

    # ---- the control: a plain AssumeRole session (no web identity anywhere in its chain)
    plain_session_name = ctx.unique_name("sim2real-xsvc-plain-")[:64]
    plain = _poll_until(
        lambda: sts.assume_role(RoleArn=plain_arn, RoleSessionName=plain_session_name,
                                DurationSeconds=900),
        lambda r: bool(r.get("Credentials", {}).get("SessionToken")),
        timeout_s=120.0,
        description="sts:AssumeRole on the freshly created control role",
    )["Credentials"]
    plain_key = plain["AccessKeyId"]
    plain_s3 = _session_client(ctx, "s3", plain_key, plain["SecretAccessKey"],
                               plain["SessionToken"])
    assert cognito_key != plain_key, "the two sessions must be distinct credentials"

    # Both make the same call. The bounded retry absorbs IAM propagation of the inline policy.
    cognito_listing = _poll_until(lambda: cognito_s3.list_buckets(),
                                  lambda r: isinstance(r.get("Buckets"), list),
                                  timeout_s=120.0,
                                  description="ListBuckets under the Cognito-vended session")
    plain_listing = _poll_until(lambda: plain_s3.list_buckets(),
                                lambda r: isinstance(r.get("Buckets"), list),
                                timeout_s=120.0,
                                description="ListBuckets under the plain assumed-role session")
    assert cognito_listing["Owner"]["ID"] == plain_listing["Owner"]["ID"], (
        f"both sessions belong to one account, so ListBuckets must report one owner: "
        f"{cognito_listing['Owner']!r} vs {plain_listing['Owner']!r}"
    )

    # ---- find both records in event history, by each session's own access key id
    t0 = time.monotonic()
    found = {}
    polls = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S and len(found) < 2:
        polls += 1
        for label, key in (("cognito", cognito_key), ("plain", plain_key)):
            if label in found:
                continue
            hits = _successful_list_buckets(_events_for_key(ct, key, window_start))
            if hits:
                found[label] = hits[0]
        if len(found) < 2:
            time.sleep(_POLL_INTERVAL_S)
    assert set(found) == {"cognito", "plain"}, (
        f"CloudTrail event history must carry a successful ListBuckets record for BOTH sessions "
        f"within {_INDEX_BUDGET_S:.0f}s; after {polls} polls only {sorted(found)!r} were found "
        f"(cognito key {cognito_key}, plain key {plain_key})"
    )

    # ---- the Cognito-vended session's record
    rec = found["cognito"]
    uid = rec["userIdentity"]
    assert rec["eventSource"] == "s3.amazonaws.com", (
        f"expected eventSource 's3.amazonaws.com', got {rec.get('eventSource')!r}"
    )
    assert rec["recipientAccountId"] == account, (
        f"expected recipientAccountId {account!r}, got {rec.get('recipientAccountId')!r}"
    )
    assert uid["type"] == "AssumedRole", (
        f"a Cognito-vended session must be audited as AssumedRole, got {uid.get('type')!r}: {uid!r}"
    )
    assert uid["arn"].endswith(f"/{COGNITO_SESSION_NAME}"), (
        f"the vended session's ARN must end in /{COGNITO_SESSION_NAME}, got {uid.get('arn')!r}"
    )
    assert uid["arn"] == f"arn:aws:sts::{account}:assumed-role/{auth_name}/{COGNITO_SESSION_NAME}", (
        f"the vended session must be a session of the pool's authenticated role {auth_name}, got "
        f"{uid.get('arn')!r}"
    )
    assert uid["accessKeyId"] == cognito_key, (
        f"the record must name the vended access key {cognito_key}, got {uid.get('accessKeyId')!r}"
    )
    issuer = uid["sessionContext"]["sessionIssuer"]
    assert issuer["type"] == "Role" and issuer["arn"] == auth_arn, (
        f"sessionIssuer must be the authenticated role {auth_arn}, got {issuer!r}"
    )
    fed = uid["sessionContext"].get("webIdFederationData")
    assert fed and fed.get("federatedProvider") == COGNITO_PROVIDER, (
        f"sessionContext.webIdFederationData.federatedProvider must be {COGNITO_PROVIDER!r}, got "
        f"webIdFederationData={fed!r}"
    )
    attrs = fed.get("attributes") or {}
    assert attrs.get(f"{COGNITO_PROVIDER}:aud") == pool_id, (
        f"the federation attributes must carry this pool as aud ({pool_id}), got {attrs!r}"
    )
    assert attrs.get(f"{COGNITO_PROVIDER}:sub") == identity_id, (
        f"the federation attributes must carry this identity as sub ({identity_id}), got {attrs!r}"
    )
    assert "authenticated" in (attrs.get(f"{COGNITO_PROVIDER}:amr") or ""), (
        f"an authenticated developer identity must be audited with amr containing "
        f"'authenticated', got {attrs.get(f'{COGNITO_PROVIDER}:amr')!r}"
    )

    # ---- the control record: same type, same operation, NO web-identity federation
    ctl = found["plain"]
    cuid = ctl["userIdentity"]
    assert cuid["type"] == "AssumedRole", (
        f"the plain control session must also be AssumedRole, got {cuid.get('type')!r}"
    )
    assert cuid["arn"] == f"arn:aws:sts::{account}:assumed-role/{plain_name}/{plain_session_name}", (
        f"the control record must name the plain session it was made by, got {cuid.get('arn')!r}"
    )
    assert cuid["sessionContext"]["sessionIssuer"]["arn"] == plain_arn, (
        f"control sessionIssuer must be {plain_arn}, got {cuid['sessionContext']['sessionIssuer']!r}"
    )
    assert not cuid["sessionContext"].get("webIdFederationData"), (
        f"a plain sts:AssumeRole session involves no web identity, so its record must carry no "
        f"webIdFederationData; got {cuid['sessionContext'].get('webIdFederationData')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
