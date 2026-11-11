"""resource-policy-deny-unless-principal-arn-locks-reads-to-one-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-deny-unless-principal-arn-locks-reads-to-one-role"
GROUP = "enforcement"
SERVICES = ["secretsmanager"]

_SESSION_NAME = "sim2real-behav-lock"
_CREDENTIAL_PROPAGATION = frozenset(
    {"UnrecognizedClientException", "InvalidClientTokenId", "SignatureDoesNotMatch"}
)


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A resource-policy Deny on GetSecretValue unless aws:PrincipalArn is the app role refuses
    another identically granted role and the owner with an explicit resource-policy deny, while the
    app role keeps reading; deleting the policy restores the other role's read.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    owner_arn = identity["Arn"]

    created = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-lock-"),
        SecretString="locked-value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    grant = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}],
    }
    app_arn, _app_name = _create_role(ctx, iam, account_id, "sim2real-behav-lock-app-", grant)
    other_arn, other_name = _create_role(ctx, iam, account_id, "sim2real-behav-lock-other-", grant)
    as_app = _client_as(ctx, _assume(sts, app_arn))
    as_other = _client_as(ctx, _assume(sts, other_arn))
    other_session = f"arn:aws:sts::{account_id}:assumed-role/{other_name}/{_SESSION_NAME}"

    def explicit_deny(principal):
        return (
            "error",
            "AccessDeniedException",
            f"User: {principal} is not authorized to perform: secretsmanager:GetSecretValue on "
            f"resource: {secret_arn} with an explicit deny in a resource-based policy",
        )

    for client, label in ((as_app, "application"), (as_other, "other")):
        before = _poll(
            lambda c=client: _read(c, secret_arn),
            lambda r: r[0] == "ok",
            timeout_s=90.0,
            interval_s=3.0,
            description=f"the {label} role's identity grant to become effective",
        )
        assert before == ("ok", "locked-value"), f"before the lock the {label} role must read; got {before!r}"

    lock = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:PrincipalArn": app_arn}},
            }
        ],
    }
    sm.put_resource_policy(SecretId=secret_arn, ResourcePolicy=json.dumps(lock), BlockPublicPolicy=True)

    other_locked = _poll(
        lambda: _read(as_other, secret_arn),
        lambda r: r[0] == "error",
        timeout_s=60.0,
        interval_s=3.0,
        description="the lock to refuse the other role",
    )
    assert other_locked == explicit_deny(other_session), (
        f"a role that is not the named principal must hit the explicit deny; got {other_locked!r}"
    )
    owner_locked = _read(sm, secret_arn)
    assert owner_locked == explicit_deny(owner_arn), (
        f"the deny applies to the owning principal as well; got {owner_locked!r}"
    )
    app_read = _read(as_app, secret_arn)
    assert app_read == ("ok", "locked-value"), (
        f"the role the condition exempts must keep reading; got {app_read!r}"
    )

    sm.delete_resource_policy(SecretId=secret_arn)
    unlocked = _poll(
        lambda: _read(as_other, secret_arn),
        lambda r: r[0] == "ok",
        timeout_s=60.0,
        interval_s=3.0,
        description="detaching the lock to restore the other role's read",
    )
    assert unlocked == ("ok", "locked-value"), f"after unlocking the other role must read; got {unlocked!r}"


def _create_role(ctx, iam, account_id, prefix, policy):
    role_name = ctx.unique_name(prefix)
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
    iam.put_role_policy(RoleName=role_name, PolicyName="read", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="read"))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
