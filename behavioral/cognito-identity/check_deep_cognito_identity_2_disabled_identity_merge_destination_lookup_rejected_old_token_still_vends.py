"""deep-cognito-identity-2-disabled-identity-merge-destination-lookup-rejected-old-token-still-vends."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-identity-2-disabled-identity-merge-destination-lookup-rejected-old-token-still-vends"
GROUP = 'identity-lifecycle'
SERVICES = ['cognito-identity']

COGNITO_LOGIN = "cognito-identity.amazonaws.com"
DISABLED = "DISABLED"
ERR_NOT_AUTHORIZED = "NotAuthorizedException"
# Retryable only while the authenticated role assignment propagates to the credential path.
ERR_POOL_CONFIG = "InvalidIdentityPoolConfigurationException"
CREDENTIALS_SESSION = "CognitoIdentityCredentials"


# ===== helpers =====

def _err(fn):
    """Call fn(); return (Code, Message) if a ClientError is raised. An unexpected SUCCESS raises,
    so an over-permissive target can never pass as a naming difference."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _retry_on(fn, codes, timeout_s=180.0, interval_s=3.0, description="call"):
    """Retry fn() while it raises one of `codes` (propagation), up to a bounded deadline."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes or time.time() >= deadline:
                raise AssertionError(f"{description} did not succeed: {code!r} {exc}") from exc
        time.sleep(interval_s)


# ===== check =====

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """After MergeDeveloperIdentities the disabled destination stays describable, LookupDeveloperIdentity
    on it is refused with NotAuthorizedException, new tokens naming it go to the survivor, and its
    pre-merge OpenID token and STS session keep working."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    dev_provider = f"login.sim2real.{ctx.unique_name('m')[-8:]}".lower()
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_disabled_merge_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": COGNITO_LOGIN},
            "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
            },
        }],
    })
    role_name = ctx.unique_name("sim2real-disabled-merge-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    partition = role_arn.split(":")[1]
    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": role_arn})

    def _assumed_arn(session):
        return f"arn:{partition}:sts::{account}:assumed-role/{role_name}/{session}"

    def _caller_arn(access_key, secret, session_token):
        return ctx.client("sts", creds={
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret,
            "aws_session_token": session_token,
        }).get_caller_identity()["Arn"]

    # --- two developer users, two identities ---------------------------------------------------
    user_dst = ctx.unique_name("sim2real-dst-")
    user_src = ctx.unique_name("sim2real-src-")
    r_dst = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_dst})
    r_src = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_src})
    id_dst, tok_dst = r_dst["IdentityId"], r_dst["Token"]
    id_src, tok_src = r_src["IdentityId"], r_src["Token"]
    assert id_dst != id_src, f"two developer users must get two identities, both got {id_dst!r}"

    # --- BOTH sessions independently authenticate at STS before the merge ----------------------
    sessions = {}
    for label, identity_id, token in (("dst", id_dst, tok_dst), ("src", id_src, tok_src)):
        session = f"sim2real-pre-{label}"
        assumed = _retry_on(
            lambda t=token, s=session: sts.assume_role_with_web_identity(
                RoleArn=role_arn, RoleSessionName=s, WebIdentityToken=t),
            {"AccessDenied"}, description=f"pre-merge AssumeRoleWithWebIdentity ({label})",
        )
        assert assumed["SubjectFromWebIdentityToken"] == identity_id, (
            f"pre-merge {label} session subject {assumed['SubjectFromWebIdentityToken']!r} != "
            f"{identity_id!r}"
        )
        c = assumed["Credentials"]
        arn = _caller_arn(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])
        assert arn == _assumed_arn(session), (
            f"pre-merge {label} STS session must authenticate as {_assumed_arn(session)!r}, got {arn!r}"
        )
        sessions[identity_id] = (session, c)

    # Pre-merge baselines on both identities: the calls asserted after the merge all work here.
    for identity_id, user, token in ((id_dst, user_dst, tok_dst), (id_src, user_src, tok_src)):
        logins = ci.describe_identity(IdentityId=identity_id).get("Logins")
        assert logins == [dev_provider], f"pre-merge Logins of {identity_id} were {logins!r}"
        looked = ci.lookup_developer_identity(
            IdentityPoolId=pool_id, IdentityId=identity_id, MaxResults=10)
        assert looked["DeveloperUserIdentifierList"] == [user], (
            f"pre-merge lookup of {identity_id} returned {looked['DeveloperUserIdentifierList']!r}"
        )
        vended = _retry_on(
            lambda i=identity_id, t=token: ci.get_credentials_for_identity(
                IdentityId=i, Logins={COGNITO_LOGIN: t}),
            {ERR_POOL_CONFIG}, description=f"pre-merge GetCredentialsForIdentity({identity_id})",
        )
        assert vended["IdentityId"] == identity_id, (
            f"pre-merge credentials were vended for {vended['IdentityId']!r}, not {identity_id!r}"
        )

    # --- merge ---------------------------------------------------------------------------------
    merged = ci.merge_developer_identities(
        SourceUserIdentifier=user_src,
        DestinationUserIdentifier=user_dst,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )

    # Determine empirically which identity is disabled, rather than assuming a direction.
    after = {i: ci.describe_identity(IdentityId=i).get("Logins") for i in (id_dst, id_src)}
    disabled = [i for i, logins in after.items() if DISABLED in (logins or [])]
    assert len(disabled) == 1, f"exactly one identity must be disabled by the merge, Logins={after!r}"
    disabled_id = disabled[0]
    survivor_id = id_src if disabled_id == id_dst else id_dst
    assert disabled_id == id_dst, (
        f"the merge must disable the DESTINATION identity {id_dst!r} and keep the SOURCE "
        f"{id_src!r}; it disabled {disabled_id!r}"
    )
    assert merged["IdentityId"] == survivor_id, (
        f"MergeDeveloperIdentities must return the survivor {survivor_id!r}, got "
        f"{merged['IdentityId']!r}"
    )

    # DescribeIdentity on the disabled identity SUCCEEDS; its Logins are replaced by the sentinel.
    assert after[disabled_id] == [DISABLED, ctx.region], (
        f"the disabled identity's Logins must be exactly [{DISABLED!r}, {ctx.region!r}], got "
        f"{after[disabled_id]!r}"
    )
    assert after[survivor_id] == [dev_provider, dev_provider], (
        f"the survivor must carry the developer provider once per merged user, got "
        f"{after[survivor_id]!r}"
    )

    # LookupDeveloperIdentity: refused on the disabled identity, complete on the survivor.
    code, msg = _err(lambda: ci.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=disabled_id, MaxResults=10))
    assert code == ERR_NOT_AUTHORIZED, (
        f"LookupDeveloperIdentity on the disabled identity must be {ERR_NOT_AUTHORIZED}, got "
        f"{code!r} ({msg!r})"
    )
    assert msg == "You do not have access to this identity", msg
    looked = ci.lookup_developer_identity(IdentityPoolId=pool_id, IdentityId=survivor_id, MaxResults=10)
    assert looked["IdentityId"] == survivor_id and sorted(looked["DeveloperUserIdentifierList"]) == \
        sorted([user_dst, user_src]), (
            f"the survivor must now own both developer users, got {looked!r}"
        )

    # GetOpenIdTokenForDeveloperIdentity naming the disabled identity is re-routed to the survivor.
    for label, user in (("dst", user_dst), ("src", user_src)):
        rerouted = ci.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id, IdentityId=disabled_id, Logins={dev_provider: user})
        assert rerouted["IdentityId"] == survivor_id, (
            f"GetOpenIdTokenForDeveloperIdentity(IdentityId=<disabled>, {label} user) must be "
            f"re-routed to the survivor {survivor_id!r}, got {rerouted['IdentityId']!r}"
        )

    # Plain GetOpenIdToken carries no disabled signal: a developer identity is refused identically
    # whether it is the survivor or the disabled one.
    for identity_id in (disabled_id, survivor_id):
        code, msg = _err(lambda i=identity_id: ci.get_open_id_token(IdentityId=i))
        assert code == ERR_NOT_AUTHORIZED, (
            f"GetOpenIdToken without logins on developer identity {identity_id} must be "
            f"{ERR_NOT_AUTHORIZED}, got {code!r} ({msg!r})"
        )
        assert msg == f"Access to Identity '{identity_id}' is forbidden.", msg

    # GetCredentialsForIdentity with each identity's OWN pre-merge token still vends -- for the
    # disabled identity too -- and the credentials authenticate.
    for identity_id, token in ((disabled_id, tok_dst), (survivor_id, tok_src)):
        vended = ci.get_credentials_for_identity(IdentityId=identity_id, Logins={COGNITO_LOGIN: token})
        assert vended["IdentityId"] == identity_id, (
            f"post-merge credentials for {identity_id} were vended for {vended['IdentityId']!r}"
        )
        c = vended["Credentials"]
        arn = _caller_arn(c["AccessKeyId"], c["SecretKey"], c["SessionToken"])
        assert arn == _assumed_arn(CREDENTIALS_SESSION), (
            f"post-merge credentials for {identity_id} must authenticate as "
            f"{_assumed_arn(CREDENTIALS_SESSION)!r}, got {arn!r}"
        )

    # The pre-merge STS session of the identity that became disabled still authenticates, and its
    # pre-merge OpenID token is still accepted by STS.
    session, c = sessions[disabled_id]
    arn = _caller_arn(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])
    assert arn == _assumed_arn(session), (
        f"the disabled identity's pre-merge STS session must still authenticate as "
        f"{_assumed_arn(session)!r}, got {arn!r}"
    )
    re_assumed = sts.assume_role_with_web_identity(
        RoleArn=role_arn, RoleSessionName="sim2real-post-dst", WebIdentityToken=tok_dst)
    assert re_assumed["SubjectFromWebIdentityToken"] == disabled_id, (
        f"STS must still accept the disabled identity's pre-merge token as subject {disabled_id!r}, "
        f"got {re_assumed['SubjectFromWebIdentityToken']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
