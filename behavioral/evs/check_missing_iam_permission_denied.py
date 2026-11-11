"""missing-iam-permission-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "missing-iam-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["evs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller whose policy denies evs:GetEnvironment gets AccessDeniedException with its exact
    message, while the authorized caller's same call gets ResourceNotFoundException with its
    exact message."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    role_name = ctx.unique_name("sim2real-evs-deny-role-")
    account_id = ctx.account
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "evs:*", "Resource": "*"}],
    }
    policy_name = "sim2real-evs-deny-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(deny_policy),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    creds = _assume_role_with_retry(sts, role_arn)

    default_evs = ctx.client("evs")
    denied_evs = ctx.client(
        "evs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    fake_env_id = "env-0000000000"
    code, message = _error(lambda: denied_evs.get_environment(environmentId=fake_env_id))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller with an explicit evs:* deny, got {code!r}"
    )
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-evs-deny-check "
        f"is not authorized to perform: evs:GetEnvironment on resource: "
        f"arn:aws:evs:{ctx.region}:{account_id}:environment/{fake_env_id} "
        f"with an explicit deny in an identity-based policy"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    control_code, control_message = _error(
        lambda: default_evs.get_environment(environmentId=fake_env_id)
    )
    assert control_code == "ResourceNotFoundException", (
        f"expected the positive control (default credentials) to reach EVS's own "
        f"not-found handling with ResourceNotFoundException, got {control_code!r}"
    )
    assert control_message == f"Environment {fake_env_id} was not found", (
        f"unexpected control message {control_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _assume_role_with_retry(sts, role_arn: str, timeout_s: float = 60.0) -> dict:
    # IAM role/policy changes are eventually consistent; retry AssumeRole briefly.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-evs-deny-check"
            )
            return resp["Credentials"]
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(5.0)
    raise AssertionError(f"could not assume role {role_arn}: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
