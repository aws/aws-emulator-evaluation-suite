"""block-public-policy-condition-key-refuses-a-put-resource-policy-that-disables-the-check."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "block-public-policy-condition-key-refuses-a-put-resource-policy-that-disables-the-check"
GROUP = "enforcement"
SERVICES = ["secretsmanager"]

_SESSION_NAME = "sim2real-behav-policy-writer"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role whose PutResourcePolicy grant requires secretsmanager:BlockPublicPolicy=true is
    refused a non-public policy sent with BlockPublicPolicy=False, attaching nothing, and the
    same request with BlockPublicPolicy=True attaches it.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]

    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-bpp-key-"),
        SecretString="guarded",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:PutResourcePolicy",
                "Resource": secret_arn,
                "Condition": {"Bool": {"secretsmanager:BlockPublicPolicy": "true"}},
            }
        ],
    }
    role_arn, role_name = _create_role(ctx, iam, account_id, policy)
    as_role = _client_as(ctx, _assume(sts, role_arn))
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}"

    document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "secretsmanager:DescribeSecret",
                    "Resource": "*",
                }
            ],
        }
    )

    # Positive first, to establish that the role's grant has propagated. Then detach with the
    # owner so the refusal below starts from a secret with no policy.
    _poll_ok(
        lambda: as_role.put_resource_policy(
            SecretId=secret_arn, ResourcePolicy=document, BlockPublicPolicy=True
        ),
        timeout_s=90.0,
    )
    attached = sm.get_resource_policy(SecretId=secret_arn)
    assert json.loads(attached["ResourcePolicy"]) == json.loads(document), (
        f"the BlockPublicPolicy=True put must attach the document; got {attached.get('ResourcePolicy')!r}"
    )
    sm.delete_resource_policy(SecretId=secret_arn)
    assert "ResourcePolicy" not in sm.get_resource_policy(SecretId=secret_arn), (
        "the owner's DeleteResourcePolicy must leave the secret with no policy"
    )

    code, message = _error(
        lambda: as_role.put_resource_policy(
            SecretId=secret_arn, ResourcePolicy=document, BlockPublicPolicy=False
        )
    )
    assert code == "AccessDeniedException", (
        f"BlockPublicPolicy=False must fail the condition; got {code!r}: {message!r}"
    )
    expected = (
        f"User: {session_arn} is not authorized to perform: secretsmanager:PutResourcePolicy on "
        f"resource: {secret_arn} because no identity-based policy allows the "
        "secretsmanager:PutResourcePolicy action"
    )
    assert message == expected, f"refusal message {message!r} != {expected!r}"
    after = sm.get_resource_policy(SecretId=secret_arn)
    assert "ResourcePolicy" not in after, (
        f"a refused PutResourcePolicy must attach nothing; got {after.get('ResourcePolicy')!r}"
    )

    # The identical request with the flag on is permitted again.
    as_role.put_resource_policy(SecretId=secret_arn, ResourcePolicy=document, BlockPublicPolicy=True)
    final = sm.get_resource_policy(SecretId=secret_arn)
    assert json.loads(final["ResourcePolicy"]) == json.loads(document), (
        f"the BlockPublicPolicy=True retry must attach the document; got {final.get('ResourcePolicy')!r}"
    )


def _create_role(ctx, iam, account_id, policy):
    role_name = ctx.unique_name("sim2real-behav-bpp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="writer", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="writer"))
    return role["Role"]["Arn"], role_name


def _assume(sts, role_arn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"assume-role never succeeded (trust policy propagation?): {last_err}")


def _client_as(ctx, creds):
    return ctx.client(
        "secretsmanager",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll_ok(fn, *, timeout_s, interval_s=3.0):
    """Retry the first permitted call only while IAM and STS propagate."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDeniedException", "UnrecognizedClientException", "InvalidClientTokenId"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the permitted call never succeeded within {timeout_s}s: {exc}")
            time.sleep(interval_s)


def _error(fn):
    """(code, message) of the refused call; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
