"""direct-oidc-assume-role-with-web-identity-grants-scoped-s3-read."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "direct-oidc-assume-role-with-web-identity-grants-scoped-s3-read"
GROUP = "web-identity-federation"
SERVICES = ["cognito-idp", "iam", "s3", "sts"]

#: Bounded convergence for the freshly created OIDC provider and role trust to become usable.
_PROPAGATE_S = 180.0


def _jwt_claims(token: str) -> dict:
    """The JSON claims carried in a JWT's payload segment."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _issuer_without_scheme(issuer: str) -> str:
    assert issuer.startswith("https://"), f"issuer {issuer!r} must be an https URL"
    return issuer[len("https://"):]


def _err(exc: ClientError) -> tuple[str, str]:
    e = exc.response.get("Error", {})
    return e.get("Code") or "", e.get("Message") or ""


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return _err(exc)
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _assume_with_web_identity(sts, **kwargs) -> dict:
    """AssumeRoleWithWebIdentity, retried only through the newly created trust's propagation."""
    deadline = time.monotonic() + _PROPAGATE_S
    while True:
        try:
            return sts.assume_role_with_web_identity(**kwargs)
        except ClientError as exc:
            code, message = _err(exc)
            if (code, message) != (
                "AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity"
            ) or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Cognito user pool ID token, federated straight through an IAM OIDC provider and a role's
    AssumeRoleWithWebIdentity trust (no Cognito Identity Pool), vends credentials that read the
    one S3 object the role's policy names and nothing else in the bucket."""
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-webid-up-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-xsvc-webid-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-xsvc-webid-user-")
    password = "Sim2Real!" + username[-12:]
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True,
    )
    id_token = idp.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["IdToken"]
    claims = _jwt_claims(id_token)
    assert claims["aud"] == client_id, f"token aud {claims.get('aud')!r} must be {client_id!r}"
    issuer_key = _issuer_without_scheme(claims["iss"])

    provider_arn = iam.create_open_id_connect_provider(
        Url=claims["iss"], ClientIDList=[client_id],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))

    bucket = ctx.unique_name("sim2real-xsvc-webid-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region},
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    granted_key = "granted.txt"
    body = ctx.unique_name("payload-").encode()
    s3.put_object(Bucket=bucket, Key=granted_key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=granted_key))

    role_name = ctx.unique_name("sim2real-xsvc-webid-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": provider_arn},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {f"{issuer_key}:aud": client_id}},
        }],
    }
    iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="scoped-read",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{granted_key}",
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="scoped-read"))

    session_name = ctx.unique_name("webid-session-")
    assumed = _assume_with_web_identity(
        sts, RoleArn=f"arn:aws:iam::{ctx.account}:role/{role_name}",
        RoleSessionName=session_name, WebIdentityToken=id_token,
    )
    assert assumed["Provider"] == issuer_key, (
        f"Provider: expected {issuer_key!r}, got {assumed.get('Provider')!r}"
    )
    assert assumed["Audience"] == client_id, (
        f"Audience: expected {client_id!r}, got {assumed.get('Audience')!r}"
    )
    assert assumed["SubjectFromWebIdentityToken"] == claims["sub"], (
        f"SubjectFromWebIdentityToken: expected {claims['sub']!r}, got "
        f"{assumed.get('SubjectFromWebIdentityToken')!r}"
    )
    assumed_arn = assumed["AssumedRoleUser"]["Arn"]
    want_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{session_name}"
    assert assumed_arn == want_arn, f"AssumedRoleUser.Arn: expected {want_arn!r}, got {assumed_arn!r}"

    creds = assumed["Credentials"]
    vended_sts = ctx.client("sts", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    identity_arn = vended_sts.get_caller_identity()["Arn"]
    assert identity_arn == want_arn, (
        f"vended GetCallerIdentity Arn: expected {want_arn!r}, got {identity_arn!r}"
    )

    vended_s3 = ctx.client("s3", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    read = vended_s3.get_object(Bucket=bucket, Key=granted_key)["Body"].read()
    assert read == body, f"vended GetObject bytes: expected {body!r}, got {read[:80]!r}"

    # The role's policy names only the one key: a second object in the same bucket is refused.
    other_key = "ungranted.txt"
    s3.put_object(Bucket=bucket, Key=other_key, Body=b"not-granted")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=other_key))
    code, message = _error(lambda: vended_s3.get_object(Bucket=bucket, Key=other_key))
    assert code == "AccessDenied", f"expected AccessDenied on the ungranted key, got {code!r}: {message!r}"
    want_message = (
        f'User: {assumed_arn} is not authorized to perform: s3:GetObject on resource: '
        f'"arn:aws:s3:::{bucket}/{other_key}" because no identity-based policy allows the '
        f's3:GetObject action'
    )
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
