"""e2e-anonymous-identity-credentials-consequence-flow."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-anonymous-identity-credentials-consequence-flow"
GROUP = "e2e"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c7", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Credentials from GetId -> GetOpenIdToken -> GetCredentialsForIdentity authenticate as the
    pool's unauthenticated role; after DeleteIdentities, GetCredentialsForIdentity and
    DescribeIdentity on the deleted IdentityId are rejected."""
    cognito = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_cog_pool_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))

    role_name, role_arn = _create_unauth_role(ctx, iam, pool_id)
    cognito.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    identity_id = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]

    open_id = cognito.get_open_id_token(IdentityId=identity_id)
    assert open_id["IdentityId"] == identity_id, (
        f"expected GetOpenIdToken to echo the identity id {identity_id!r}, got {open_id['IdentityId']!r}"
    )
    assert open_id["Token"], f"expected a non-empty OpenId token, got {open_id['Token']!r}"

    # IAM role trust-policy propagation can lag a few seconds behind SetIdentityPoolRoles.
    creds = _poll_until(
        lambda: _try_get_credentials(cognito, identity_id),
        lambda c: c is not None,
        timeout_s=90,
        interval_s=5.0,
        description="GetCredentialsForIdentity resolves the unauthenticated role",
    )
    caller = _sts_client_from_credentials(ctx, creds).get_caller_identity()
    assert role_name in caller["Arn"], (
        f"expected the vended STS credentials to assume {role_name!r}, got caller Arn {caller['Arn']!r}"
    )
    assert ":assumed-role/" in caller["Arn"], (
        f"expected an assumed-role Arn from the vended credentials, got {caller['Arn']!r}"
    )

    # positive control before the break: both calls succeed for the live identity.
    desc = cognito.describe_identity(IdentityId=identity_id)
    assert desc["IdentityId"] == identity_id, (
        f"expected DescribeIdentity to echo {identity_id!r} before deletion, got {desc['IdentityId']!r}"
    )
    pre_delete_creds = cognito.get_credentials_for_identity(IdentityId=identity_id)
    assert pre_delete_creds["IdentityId"] == identity_id, (
        "expected GetCredentialsForIdentity to succeed for the live identity before deletion, "
        f"got IdentityId {pre_delete_creds['IdentityId']!r}"
    )

    delete_resp = cognito.delete_identities(IdentityIdsToDelete=[identity_id])
    unprocessed = delete_resp.get("UnprocessedIdentityIds", [])
    assert unprocessed == [], (
        f"expected DeleteIdentities to process {identity_id!r} cleanly, got unprocessed={unprocessed!r}"
    )

    err_code, err_message = _client_error(
        lambda: cognito.get_credentials_for_identity(IdentityId=identity_id), wait_s=60.0
    )
    assert err_code == "ResourceNotFoundException", (
        f"expected GetCredentialsForIdentity on the deleted identity {identity_id!r} to raise "
        f"ResourceNotFoundException, got {(err_code, err_message)!r}"
    )
    assert err_message == f"Identity '{identity_id}' not found.", err_message

    err2_code, err2_message = _client_error(
        lambda: cognito.describe_identity(IdentityId=identity_id), wait_s=60.0
    )
    assert err2_code == "ResourceNotFoundException", (
        f"expected DescribeIdentity on the deleted identity {identity_id!r} to raise "
        f"ResourceNotFoundException, got {(err2_code, err2_message)!r}"
    )
    assert err2_message == f"Identity '{identity_id}' not found.", err2_message


def _create_unauth_role(ctx, iam, pool_id):
    role_name = ctx.unique_name("sim2real-cog-unauth-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
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
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="AllowGetCallerIdentity",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}],
            }
        ),
    )

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="AllowGetCallerIdentity")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return role_name, role_arn


def _try_get_credentials(cognito, identity_id):
    try:
        return cognito.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
    except ClientError:
        return None


def _client_error(fn, *, wait_s=0.0, interval_s=3.0):
    """Call fn() until it raises a ClientError, for at most ``wait_s``; return (code, message). A
    call that still succeeds at the deadline raises."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _sts_client_from_credentials(ctx, creds):
    """An STS client on this run's target, signed with the vended credentials."""
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
