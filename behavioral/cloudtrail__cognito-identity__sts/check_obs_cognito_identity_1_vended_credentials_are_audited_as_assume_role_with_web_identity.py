"""obs-cognito-identity-1-vended-credentials-are-audited-as-assume-role-with-web-identity."""
from __future__ import annotations

# A developer-authenticated login avoids cognito-idp; either login makes Cognito broker the same
# STS AssumeRoleWithWebIdentity on the pool's authenticated role.

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cognito-identity-1-vended-credentials-are-audited-as-assume-role-with-web-identity"
GROUP = "eventing"
SERVICES = ["cloudtrail", "cognito-identity", "sts"]

#: Ceiling for this run's own CreateIdentityPool record to become findable. It is the calibration
#: marker: the STS deadline below is derived from how long THIS marker took, in THIS run.
_MARKER_CEILING_S = 600.0
#: The STS record's deadline is 4x the marker's measured index latency, clamped to this range.
_DEADLINE_MULTIPLE = 4.0
_STS_FLOOR_S = 60.0
_STS_CEILING_S = 900.0
#: A new role trust is not immediately usable through Cognito (InvalidIdentityPoolConfiguration).
_PROPAGATION_BUDGET_S = 120.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

_SESSION_NAME = "CognitoIdentityCredentials"



def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded). Returns (events, pages)."""
    out = []
    nxt = None
    for page in range(1, _PAGE_CEILING + 1):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out, page
    raise AssertionError(
        f"LookupEvents paged past {_PAGE_CEILING} pages without exhausting; refusing to assert "
        "membership in a truncated result"
    )


def _find(ct, event_name, start, predicate):
    """One full scan of event history for `event_name`. Returns (record|None, pages, n_events)."""
    events, pages = _lookup_all(
        ct,
        StartTime=start,
        EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
    )
    for ev in events:
        raw = json.loads(ev["CloudTrailEvent"])
        if predicate(raw):
            return raw, pages, len(events)
    return None, pages, len(events)


def _params(raw):
    return raw.get("requestParameters") or {}


def _delete_role(iam, name):
    try:
        for pol in iam.list_role_policies(RoleName=name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _vend_with_retry(ci, identity_id, token):
    """GetCredentialsForIdentity, retrying ONLY the trust-propagation class, bounded, then raising."""
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    while True:
        try:
            return ci.get_credentials_for_identity(
                IdentityId=identity_id, Logins={"cognito-identity.amazonaws.com": token}
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            if (
                code != "InvalidIdentityPoolConfigurationException"
                or message != "Invalid identity pool configuration. Check assigned IAM roles for this pool."
                or time.monotonic() >= deadline
            ):
                raise AssertionError(
                    f"GetCredentialsForIdentity did not vend credentials within "
                    f"{_PROPAGATION_BUDGET_S:.0f}s of the role being assigned; last error {code!r} ({message!r})"
                ) from exc
            time.sleep(3.0)




@tags(
    "axis:happy-path",
    "dp:api",
    "plane:data",
    "concern:eventing",
    "concern:data-plane",
    "concern:e2e",
    "cap:c2",
)
def run(ctx) -> None:
    """Credentials an identity pool vends are audited in CloudTrail as the STS
    AssumeRoleWithWebIdentity Cognito brokered, naming the pool's role, the identity and the exact
    access key returned; GetCallerIdentity with them reports that same assumed role.
    """
    ct = ctx.client("cloudtrail")
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    pool_name = ctx.unique_name("sim2real_xsvc_ctsts_").replace("-", "_")
    provider = f"sim2real.{pool_name[-12:]}"

    t0 = time.monotonic()
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=provider,
        IdentityPoolTags={"sim2real": CHECK[:64]},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-xsvc-ctsts-auth-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
            },
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK[:256]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": role_arn})

    login = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={provider: f"user-{pool_name[-12:]}"}
    )
    identity_id = login["IdentityId"]

    vended = _vend_with_retry(ci, identity_id, login["Token"])
    assert vended["IdentityId"] == identity_id, (
        f"GetCredentialsForIdentity answered for {vended.get('IdentityId')!r}, not {identity_id!r}"
    )
    creds = vended["Credentials"]
    access_key = creds["AccessKeyId"]
    t_vend = time.monotonic()

    # Use the vended credentials: STS must report them as a session of exactly the pool's role.
    session_sts = ctx.client(
        "sts",
        region=ctx.region,
        creds={
            "aws_access_key_id": access_key,
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    me = session_sts.get_caller_identity()
    expected_session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME}"
    assert me["Arn"] == expected_session_arn, (
        f"the vended credentials must be a session of the pool's authenticated role: expected "
        f"{expected_session_arn!r}, actual {me.get('Arn')!r}"
    )

    # Freeze-check marker: a management event emitted strictly AFTER the STS act.
    ci.describe_identity_pool(IdentityPoolId=pool_id)

    # Calibrate: the STS record's deadline derives from this run's CreateIdentityPool index latency.
    marker = None
    pages = n_events = 0
    while marker is None:
        marker, pages, n_events = _find(
            ct, "CreateIdentityPool", window_start,
            lambda r: _params(r).get("identityPoolName") == pool_name,
        )
        if marker is None:
            assert time.monotonic() - t0 < _MARKER_CEILING_S, (
                f"CloudTrail event history never surfaced this run's own CreateIdentityPool for "
                f"{pool_name!r} within {_MARKER_CEILING_S:.0f}s (last scan: {pages} page(s), "
                f"{n_events} CreateIdentityPool events, none ours); nothing downstream can be judged"
            )
            time.sleep(_POLL_INTERVAL_S)
    marker_latency_s = time.monotonic() - t0
    sts_deadline_s = min(max(_DEADLINE_MULTIPLE * marker_latency_s, _STS_FLOOR_S), _STS_CEILING_S)

    # A later marker distinguishes a frozen index from one that omitted the STS record.
    record = None
    later_marker_seen = False
    polls = 0
    while True:
        polls += 1
        record, pages, n_events = _find(
            ct, "AssumeRoleWithWebIdentity", window_start,
            lambda r: _params(r).get("roleArn") == role_arn,
        )
        if record is not None:
            break
        if not later_marker_seen:
            later, _, _ = _find(
                ct, "DescribeIdentityPool", window_start,
                lambda r: _params(r).get("identityPoolId") == pool_id and not r.get("errorCode"),
            )
            later_marker_seen = later is not None
        if time.monotonic() - t_vend >= sts_deadline_s:
            state = (
                "the index is LIVE (a DescribeIdentityPool emitted after the STS act was indexed) "
                "yet omitted the STS record"
                if later_marker_seen
                else "the index looks FROZEN (the later DescribeIdentityPool marker never surfaced "
                "either)"
            )
            raise AssertionError(
                f"no AssumeRoleWithWebIdentity record naming roleArn {role_arn!r} within "
                f"{sts_deadline_s:.0f}s ({_DEADLINE_MULTIPLE}x the {marker_latency_s:.0f}s the "
                f"CreateIdentityPool marker took) after {polls} polls; last scan returned {pages} "
                f"page(s) holding {n_events} AssumeRoleWithWebIdentity events; {state}"
            )
        time.sleep(_POLL_INTERVAL_S)

    assert record.get("eventSource") == "sts.amazonaws.com", (
        f"Cognito-vended credentials are minted by STS: expected eventSource 'sts.amazonaws.com', "
        f"actual {record.get('eventSource')!r}"
    )
    assert record.get("eventName") == "AssumeRoleWithWebIdentity", (
        f"expected eventName 'AssumeRoleWithWebIdentity', actual {record.get('eventName')!r}"
    )
    assert _params(record).get("roleArn") == role_arn, (
        f"requestParameters.roleArn: expected the pool's role {role_arn!r}, actual "
        f"{_params(record).get('roleArn')!r}"
    )
    assert _params(record).get("roleSessionName") == _SESSION_NAME, (
        f"requestParameters.roleSessionName: expected {_SESSION_NAME!r}, actual "
        f"{_params(record).get('roleSessionName')!r}"
    )
    assert record.get("errorCode") is None, (
        f"a call that vended credentials must record no errorCode, actual {record.get('errorCode')!r}"
    )
    assert record.get("awsRegion") == ctx.region, (
        f"the brokered STS call is audited in the pool's region: expected {ctx.region!r}, actual "
        f"{record.get('awsRegion')!r}"
    )
    assert record.get("recipientAccountId") == account, (
        f"the record belongs to the role owner's account: expected {account!r}, actual "
        f"{record.get('recipientAccountId')!r}"
    )

    # The observed userIdentity: the Cognito identity itself, not the IAM caller of this check.
    ident = record.get("userIdentity") or {}
    assert ident.get("type") == "WebIdentityUser", (
        f"userIdentity.type: expected 'WebIdentityUser', actual {ident.get('type')!r}; full "
        f"userIdentity {json.dumps(ident)[:300]!r}"
    )
    assert ident.get("identityProvider") == "cognito-identity.amazonaws.com", (
        f"userIdentity.identityProvider: expected 'cognito-identity.amazonaws.com', actual "
        f"{ident.get('identityProvider')!r}"
    )
    assert ident.get("userName") == identity_id, (
        f"userIdentity.userName: expected the Cognito identity {identity_id!r}, actual "
        f"{ident.get('userName')!r}"
    )
    expected_principal = f"cognito-identity.amazonaws.com:{pool_id}:{identity_id}"
    assert ident.get("principalId") == expected_principal, (
        f"userIdentity.principalId: expected {expected_principal!r}, actual "
        f"{ident.get('principalId')!r}"
    )

    resp = record.get("responseElements") or {}
    assert resp.get("subjectFromWebIdentityToken") == identity_id, (
        f"responseElements.subjectFromWebIdentityToken: expected {identity_id!r}, actual "
        f"{resp.get('subjectFromWebIdentityToken')!r}"
    )
    recorded_key = (resp.get("credentials") or {}).get("accessKeyId")
    assert recorded_key == access_key, (
        f"the audited access key must be the one Cognito returned to the caller: expected "
        f"{access_key!r}, actual {recorded_key!r}"
    )
    assumed = (resp.get("assumedRoleUser") or {}).get("arn")
    assert assumed == me["Arn"], (
        f"responseElements.assumedRoleUser.arn must equal the caller identity the vended "
        f"credentials report: expected {me['Arn']!r}, actual {assumed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
