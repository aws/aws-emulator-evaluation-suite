"""identity-policy-deny-overrides-a-resource-policy-allow-for-the-same-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-policy-deny-overrides-a-resource-policy-allow-for-the-same-role"
GROUP = "enforcement"
SERVICES = ["secretsmanager"]

_SESSION_NAME = "sim2real-behav-deny-wins"
_CREDENTIAL_PROPAGATION = frozenset(
    {"UnrecognizedClientException", "InvalidClientTokenId", "SignatureDoesNotMatch"}
)


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Deny in a role's identity policy overrides a resource-policy Allow naming it: the role reads
    via the resource policy alone, is refused with an explicit identity-based deny once the Deny is
    added (resource policy unchanged), and reads again when the Deny is removed.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]

    created = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-denywins-"),
        SecretString="deny-wins-value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    role_name = ctx.unique_name("sim2real-behav-denywins-role-")
    role_arn = _create_role(ctx, iam, account_id, role_name)
    as_role = _client_as(ctx, _assume(sts, role_arn))
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}"

    allow = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    _put_resource_policy(sm, secret_arn, allow)

    granted = _poll(
        lambda: _read(as_role, secret_arn),
        lambda r: r[0] == "ok",
        timeout_s=90.0,
        interval_s=3.0,
        description="the resource-policy Allow to admit the role",
    )
    assert granted == ("ok", "deny-wins-value"), f"the resource policy alone must grant the read; got {granted!r}"

    deny = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="deny-read", PolicyDocument=json.dumps(deny))
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, "deny-read"))
    refused = _poll(
        lambda: _read(as_role, secret_arn),
        lambda r: r[0] == "error",
        timeout_s=90.0,
        interval_s=3.0,
        description="the identity Deny to take effect",
    )
    assert refused == (
        "error",
        "AccessDeniedException",
        f"User: {session_arn} is not authorized to perform: secretsmanager:GetSecretValue on "
        f"resource: {secret_arn} with an explicit deny in an identity-based policy",
    ), f"an identity Deny must override the resource-policy Allow; got {refused!r}"
    still = json.loads(sm.get_resource_policy(SecretId=secret_arn)["ResourcePolicy"])
    assert still == allow, f"the resource policy must be unchanged while the Deny applies; got {still!r}"

    iam.delete_role_policy(RoleName=role_name, PolicyName="deny-read")
    restored = _poll(
        lambda: _read(as_role, secret_arn),
        lambda r: r[0] == "ok",
        timeout_s=90.0,
        interval_s=3.0,
        description="removing the identity Deny to restore the read",
    )
    assert restored == ("ok", "deny-wins-value"), f"without the Deny the role must read again; got {restored!r}"


def _create_role(ctx, iam, account_id, role_name):
    """A role whose only grant to the secret is the resource policy."""
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
    return role["Role"]["Arn"]


def _delete_role_policy(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _put_resource_policy(sm, secret_arn, policy, timeout_s=60.0, interval_s=3.0):
    """Secrets Manager resolves the Principal ARN at attach time; a just-created role surfaces as
    MalformedPolicyDocumentException until IAM has propagated it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.put_resource_policy(SecretId=secret_arn, ResourcePolicy=json.dumps(policy), BlockPublicPolicy=True)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocumentException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the policy naming the new role was never accepted: {exc}")
            time.sleep(interval_s)


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
