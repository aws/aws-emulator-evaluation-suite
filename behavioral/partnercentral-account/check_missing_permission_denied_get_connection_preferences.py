"""missing-permission-denied-get-connection-preferences."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "missing-permission-denied-get-connection-preferences"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the caller's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


def _restricted_pca_client(ctx, sts_creds):
    """The us-east-1 partnercentral-account client of _pca_client, signed with the freshly
    assumed role's credentials instead of ctx's own identity."""
    explicit = {
        "aws_access_key_id": sts_creds["AccessKeyId"],
        "aws_secret_access_key": sts_creds["SecretAccessKey"],
        "aws_session_token": sts_creds["SessionToken"],
    }
    return ctx.client("partnercentral-account", region="us-east-1", creds=explicit)


def _denial(fn):
    """Call fn(); return its error code and message. Fresh role credentials are briefly unknown to
    the service, so UnrecognizedClientException is retried for up to 30s. An unexpected SUCCESS
    raises."""
    deadline = time.monotonic() + 30
    while True:
        try:
            result = fn()
        except ClientError as e:
            error = e.response["Error"]
            if error["Code"] == "UnrecognizedClientException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            return error["Code"], error["Message"]
        raise AssertionError(f"expected the restricted call to be denied, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConnectionPreferences through an IAM role with no policy fails with AccessDeniedException and the exact
    implicit-deny message, while the caller's own call succeeds; once the role is granted that one action, the
    same call succeeds within the IAM propagation window.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    pca = _pca_client(ctx)

    # Positive control up front: normal credentials can call the API.
    pca.get_connection_preferences(Catalog="AWS")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-pca-deny-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # No permissions policy is attached to this role at all -> implicit deny on every action.

    session_name = "sim2real-probe-" + uuid.uuid4().hex[:8]
    deadline = time.monotonic() + 30
    assumed = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            break
        except ClientError as e:
            last_err = e
            time.sleep(2)
    assert assumed is not None, f"could not assume freshly-created role: {last_err}"

    restricted_pca = _restricted_pca_client(ctx, assumed["Credentials"])

    code, message = _denial(lambda: restricted_pca.get_connection_preferences(Catalog="AWS"))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        "authorized to perform: partnercentral:GetConnectionPreferences because no "
        "identity-based policy allows the partnercentral:GetConnectionPreferences action"
    ), message

    # Restore: grant exactly the one missing permission and demand the identical call then
    # succeeds. Bounded retry, not a sleep -- IAM policy attachment is eventually consistent.
    policy_name = "sim2real-allow-get-connection-preferences"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "partnercentral:GetConnectionPreferences",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    restore_deadline = time.monotonic() + 60
    last_restore_err = None
    while time.monotonic() < restore_deadline:
        try:
            restricted_pca.get_connection_preferences(Catalog="AWS")
            break
        except ClientError as e:
            last_restore_err = e
            time.sleep(3)
    else:
        raise AssertionError(
            "expected the identical call to succeed within 60s once the missing permission "
            f"was granted; last error: {last_restore_err}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
