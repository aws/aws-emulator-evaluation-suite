"""batch-get-secret-value-filters-form-denied-without-list-secrets-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-secret-value-filters-form-denied-without-list-secrets-permission"
GROUP = "enforcement"
SERVICES = ["secretsmanager"]

_SESSION_NAME = "sim2real-behav-batch-reader"
_CREDENTIAL_PROPAGATION = frozenset(
    {"UnrecognizedClientException", "InvalidClientTokenId", "SignatureDoesNotMatch"}
)


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role allowed only BatchGetSecretValue and GetSecretValue reads a secret by SecretIdList,
    but the Filters form also needs secretsmanager:ListSecrets and is refused until it is granted.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-batchfilter-")
    created = sm.create_secret(
        Name=name, SecretString="batch-value", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    role_name = ctx.unique_name("sim2real-behav-batchfilter-role-")
    role_arn = _create_role(ctx, iam, account_id, role_name)

    def statements(with_list):
        stmts = [
            {"Effect": "Allow", "Action": "secretsmanager:BatchGetSecretValue", "Resource": "*"},
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
        ]
        if with_list:
            stmts.append({"Effect": "Allow", "Action": "secretsmanager:ListSecrets", "Resource": "*"})
        return json.dumps({"Version": "2012-10-17", "Statement": stmts})

    iam.put_role_policy(RoleName=role_name, PolicyName="batch", PolicyDocument=statements(False))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="batch"))
    as_role = _client_as(ctx, _assume(sts, role_arn))
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}"

    def by_ids():
        r = as_role.batch_get_secret_value(SecretIdList=[secret_arn])
        return [(v["ARN"], v["SecretString"]) for v in r["SecretValues"]], r.get("Errors", [])

    def by_filter():
        r = as_role.batch_get_secret_value(Filters=[{"Key": "name", "Values": [name]}])
        return [(v["ARN"], v["SecretString"]) for v in r["SecretValues"]], r.get("Errors", [])

    # IAM propagation can answer allow on one request and deny on the next, so the grant counts
    # as effective only after three consecutive successes.
    streak = []

    def settled(r):
        streak.append(r[0] == "ok")
        return streak[-3:] == [True, True, True]

    listed = _poll(
        lambda: _call(by_ids),
        settled,
        timeout_s=120.0,
        interval_s=2.0,
        description="the role's batch grant to become effective on three consecutive calls",
    )
    assert listed == ("ok", ([(secret_arn, "batch-value")], [])), (
        f"the SecretIdList form must return the secret with no errors; got {listed!r}"
    )

    refused = _call(by_filter)
    expected = (
        "error",
        "AccessDeniedException",
        f"User: {session_arn} is not authorized to perform: secretsmanager:ListSecrets because no "
        "identity-based policy allows the secretsmanager:ListSecrets action",
    )
    assert refused == expected, (
        f"the Filters form without secretsmanager:ListSecrets must be refused; got {refused!r}"
    )
    again = _call(by_ids)
    assert again == listed, f"the SecretIdList form must keep working beside the refusal; got {again!r}"

    iam.put_role_policy(RoleName=role_name, PolicyName="batch", PolicyDocument=statements(True))
    served = _poll(
        lambda: _call(by_filter),
        lambda r: r[0] == "ok",
        timeout_s=90.0,
        interval_s=3.0,
        description="secretsmanager:ListSecrets to become effective for the role",
    )
    assert served == ("ok", ([(secret_arn, "batch-value")], [])), (
        f"with ListSecrets the Filters form must return exactly the named secret; got {served!r}"
    )


def _create_role(ctx, iam, account_id, role_name):
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


def _call(fn):
    try:
        return ("ok", fn())
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
