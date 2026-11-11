"""e2e-credentials-rejected-without-role-mapping."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-credentials-rejected-without-role-mapping"
GROUP = "e2e"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity on a pool with no roles is refused with
    InvalidIdentityPoolConfigurationException and the exact message; after SetIdentityPoolRoles the
    same identity gets credentials that STS resolves to the configured role."""
    cognito = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool_id = cognito.create_identity_pool(
        IdentityPoolName=pool_name, AllowUnauthenticatedIdentities=True
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]

    err = _client_error(lambda: cognito.get_credentials_for_identity(IdentityId=identity_id))
    assert err == (
        "InvalidIdentityPoolConfigurationException",
        "Invalid identity pool configuration. Check assigned IAM roles for this pool.",
    ), err

    role_name = ctx.unique_name("sim2real-behav-role-")[:64]
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    cognito.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    # IAM role trust-policy propagation is eventually consistent (no fixed SLA); poll rather
    # than assert immediately: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    credentials = _wait_for_credentials(cognito, identity_id)
    assert credentials["AccessKeyId"]
    assert credentials["SessionToken"]

    # Independent terminal read at the destination: the vended credentials must actually work
    # against STS, not merely be present fields, and must resolve to the role we configured —
    # not the pool's own caller or some other principal.
    caller = _client_from_credentials(ctx, "sts", credentials).get_caller_identity()
    assert f"assumed-role/{role_name}/" in caller["Arn"], (
        f"vended credentials should assume {role_name!r}, got {caller['Arn']!r}"
    )


def _client_error(fn):
    """Call fn(); return the ClientError's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _wait_for_credentials(cognito, identity_id, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cognito.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"GetCredentialsForIdentity never succeeded once roles were configured: {last_err}")


def _client_from_credentials(ctx, service, creds):
    """A client on this run's target, signed with the vended credentials."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
