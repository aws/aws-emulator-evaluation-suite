"""wildcard-principal-scoped-by-principal-account-is-not-public-and-admits-a-same-account-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wildcard-principal-scoped-by-principal-account-is-not-public-and-admits-a-same-account-role"
GROUP = "enforcement"
SERVICES = ["secretsmanager"]

_SESSION_NAME = "sim2real-behav-account-reader"
_PUBLIC_POLICY_MESSAGE = "You can not attach a resource policy that grants Public access to your secret."
_CREDENTIAL_PROPAGATION = frozenset(
    {"UnrecognizedClientException", "InvalidClientTokenId", "SignatureDoesNotMatch"}
)


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BlockPublicPolicy refuses an unconditioned Principal:"*" Allow but accepts it scoped by
    aws:PrincipalAccount; that policy alone lets a same-account role read, until it is detached.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]

    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-acctscope-"),
        SecretString="account-scoped-value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    role_arn, role_name = _create_role(ctx, iam, account_id)
    as_role = _client_as(ctx, _assume(sts, role_arn))
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}"
    no_grant = (
        "error",
        "AccessDeniedException",
        f"User: {session_arn} is not authorized to perform: secretsmanager:GetSecretValue on "
        f"resource: {secret_arn} because no identity-based policy allows the "
        "secretsmanager:GetSecretValue action",
    )

    before = _poll(
        lambda: _read(as_role, secret_arn),
        lambda r: r[0] == "error" and r[1] not in _CREDENTIAL_PROPAGATION,
        timeout_s=60.0,
        interval_s=3.0,
        description="the role's credentials to be recognized",
    )
    assert before == no_grant, f"with no policy the role must be refused; got {before!r}"

    statement = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "secretsmanager:GetSecretValue",
        "Resource": "*",
    }
    public_doc = {"Version": "2012-10-17", "Statement": [statement]}
    scoped_doc = {
        "Version": "2012-10-17",
        "Statement": [{**statement, "Condition": {"StringEquals": {"aws:PrincipalAccount": account_id}}}],
    }

    code, message = _error(
        lambda: sm.put_resource_policy(
            SecretId=secret_arn, ResourcePolicy=json.dumps(public_doc), BlockPublicPolicy=True
        )
    )
    assert (code, message) == ("PublicPolicyException", _PUBLIC_POLICY_MESSAGE), (
        f"an unconditioned wildcard Allow must be refused as public; got {code!r}: {message!r}"
    )
    assert "ResourcePolicy" not in sm.get_resource_policy(SecretId=secret_arn), (
        "the refused public policy must not be attached"
    )

    sm.put_resource_policy(
        SecretId=secret_arn, ResourcePolicy=json.dumps(scoped_doc), BlockPublicPolicy=True
    )
    stored = json.loads(sm.get_resource_policy(SecretId=secret_arn)["ResourcePolicy"])
    assert stored["Statement"][0]["Condition"] == {"StringEquals": {"aws:PrincipalAccount": account_id}}, (
        f"the account-scoped policy must be stored with its condition; got {stored!r}"
    )

    granted = _poll(
        lambda: _read(as_role, secret_arn),
        lambda r: r[0] == "ok",
        timeout_s=60.0,
        interval_s=3.0,
        description="the account-scoped resource policy to admit the role",
    )
    assert granted == ("ok", "account-scoped-value"), (
        f"the account-scoped wildcard policy must grant the same-account role; got {granted!r}"
    )

    sm.delete_resource_policy(SecretId=secret_arn)
    revoked = _poll(
        lambda: _read(as_role, secret_arn),
        lambda r: r[0] == "error",
        timeout_s=60.0,
        interval_s=3.0,
        description="detaching the policy to revoke the role's only grant",
    )
    assert revoked == no_grant, f"after detaching the policy the role must be refused; got {revoked!r}"


def _create_role(ctx, iam, account_id):
    """A role with NO identity-based permissions."""
    role_name = ctx.unique_name("sim2real-behav-acctscope-role-")
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


def _read(client, secret_id):
    try:
        return ("ok", client.get_secret_value(SecretId=secret_id)["SecretString"])
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return ("error", error.get("Code"), error.get("Message"))


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last) or (last[0] == "error" and last[1] in _CREDENTIAL_PROPAGATION):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


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
