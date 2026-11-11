"""e2e-principal-tags-flow-into-sts-session-tags."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-principal-tags-flow-into-sts-session-tags"
GROUP = "e2e"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c7", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PrincipalTags supplied directly to a developer identity surface as STS session tags;
    SetPrincipalTagAttributeMap rejects that same provider since dev-auth providers aren't
    part of the pool's federated-provider configuration."""
    cog = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    dev_provider = ctx.unique_name("sim2real-tagdevprov-")
    login_provider = "graph.facebook.com"
    pool = cog.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-tagpool-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
        SupportedLoginProviders={login_provider: ctx.unique_name("app-")},
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cog.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-tagrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "authenticated"
                    },
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # Permission is gated on the exact value of the "department" principal tag: iam:GetRole
    # succeeds only if the tag supplied below lands on the STS session with the value
    # "engineering", and iam:ListRoleTags (gated on a value never supplied) is refused.
    # sts:GetCallerIdentity needs no permission, so its success says nothing about the tag.
    policy_name = "gated-by-department-tag"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:GetRole",
                        "Resource": role_arn,
                        "Condition": {
                            "StringEquals": {"aws:PrincipalTag/department": "engineering"}
                        },
                    },
                    {
                        "Effect": "Allow",
                        "Action": "iam:ListRoleTags",
                        "Resource": role_arn,
                        "Condition": {
                            "StringEquals": {"aws:PrincipalTag/department": "finance"}
                        },
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    cog.set_identity_pool_roles(
        IdentityPoolId=pool_id,
        Roles={"authenticated": role_arn},
    )

    # Positive control: the same call succeeds for a provider that IS part of the pool's
    # federated-provider config, proving the account/credentials are healthy for this API and
    # that the rejection below is specific to the dev-auth provider, not a blanket failure.
    control_resp = cog.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=login_provider,
        UseDefaults=False,
        PrincipalTags={"department": "department"},
    )
    assert control_resp["PrincipalTags"] == {"department": "department"}, control_resp

    # SetPrincipalTagAttributeMap validates its IdentityProviderName against the pool's
    # federated-provider config (SupportedLoginProviders / CognitoIdentityProviders /
    # SamlProviderARNs / OpenIdConnectProviderARNs) — a developer-authenticated provider is
    # deliberately excluded from that set on real AWS, so this always rejects with
    # InvalidParameterException, confirmed empirically below.
    err = _client_error(
        lambda: cog.set_principal_tag_attribute_map(
            IdentityPoolId=pool_id,
            IdentityProviderName=dev_provider,
            UseDefaults=False,
            PrincipalTags={"department": "department"},
        )
    )
    assert err == ("InvalidParameterException", f"Provider {dev_provider} not configured for Identity Pool"), (
        f"expected InvalidParameterException for a dev-auth IdentityProviderName, got {err!r}"
    )

    # For developer-authenticated identities there is no upstream token to map claims from
    # (see the "DevAuth" row in the provider-mappings table: "Not applicable") — the
    # PrincipalTags supplied directly to GetOpenIdTokenForDeveloperIdentity are baked into the
    # returned OpenID token and surface as STS session tags once that token is presented to
    # AssumeRoleWithWebIdentity.
    #
    # Developer-authenticated identities are a Basic (Classic) authflow construct: real AWS
    # rejects them from the Enhanced flow's GetCredentialsForIdentity (NotAuthorizedException /
    # "Please provide a valid public provider"), so credentials must come from
    # GetOpenIdTokenForDeveloperIdentity -> STS AssumeRoleWithWebIdentity directly.
    dev_user = ctx.unique_name("sim2real-taguser-")
    logins = {dev_provider: dev_user}
    token_resp = cog.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins=logins,
        PrincipalTags={"department": "engineering"},
    )
    identity_id = token_resp["IdentityId"]
    web_identity_token = token_resp["Token"]

    sts_bootstrap = ctx.client("sts")
    session_name = identity_id.split(":")[-1]
    assumed = _poll_until_success(
        lambda: sts_bootstrap.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=web_identity_token,
        ),
        retryable_codes={"AccessDenied", "InvalidIdentityToken"},
        timeout_s=60.0,
        interval_s=3.0,
    )
    creds = assumed["Credentials"]

    sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    caller = _poll_until_success(
        sts.get_caller_identity,
        retryable_codes={"AccessDenied"},
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert f"assumed-role/{role_name}/" in caller["Arn"], caller["Arn"]

    session_creds = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    tagged_iam = ctx.client("iam", creds=session_creds)
    budget = max(1.0, min(60.0, (ctx.time_left() or 60.0) - 5.0))
    got = _poll_until_success(
        lambda: tagged_iam.get_role(RoleName=role_name),
        retryable_codes={"AccessDenied"},
        timeout_s=budget,
        interval_s=3.0,
    )
    assert got["Role"]["Arn"] == role_arn, (
        f"iam:GetRole allowed only for PrincipalTag department=engineering returned "
        f"{got['Role'].get('Arn')!r}"
    )
    denied_code, denied_message = _client_error(lambda: tagged_iam.list_role_tags(RoleName=role_name))
    assert denied_code == "AccessDenied", (
        f"iam:ListRoleTags is allowed only for PrincipalTag department=finance, so the "
        f"department=engineering session must be refused with AccessDenied; got {denied_code!r}"
    )
    denied_head = (
        f"User: {caller['Arn']} is not authorized to perform: iam:ListRoleTags on resource: "
        f"role {role_name} because no identity-based policy allows the iam:ListRoleTags action"
    )
    assert denied_message == _expected_denial(denied_message, denied_head), (
        f"expected the exact AccessDenied message AWS returns, got {denied_message!r}"
    )


def _expected_denial(message, head):
    """``head`` plus the authorization-details pointer IAM appends, built from the per-request
    authorization id and console region that ``message`` carries; ``head`` alone when it has none."""
    found = re.search(
        r"\. Go to https://([a-z0-9-]+)\.console\.aws\.amazon\.com/iam/home\?region=\1"
        r"#/authorization-details/(\w+) for complete details, or call the GetRequestAuthorizationDetails "
        r"API with the following authorization id: \2$",
        message or "",
    )
    if found is None:
        return head
    region, auth_id = found.groups()
    return (
        f"{head}. Go to https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/authorization-details/{auth_id} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth_id}"
    )


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until_success(fn, *, retryable_codes, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in retryable_codes:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"never succeeded within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
