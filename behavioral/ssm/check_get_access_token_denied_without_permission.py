"""get-access-token-denied-without-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-access-token-denied-without-permission"
GROUP = "error-semantics"
SERVICES = ["ssm"]


def _error(fn):
    """Return the ClientError error dict; raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"GetAccessToken unexpectedly SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAccessToken without ssm:GetAccessToken fails AccessDeniedException with IAM's message.

    A privileged caller gets a non-authorization error for the same request id, and granting the
    permission moves the restricted principal onto that same error, so the denial is IAM's."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    admin_ssm = ctx.client("ssm")
    account_id = sts.get_caller_identity()["Account"]

    bogus_id = "oi-000000000000"

    # Whatever error the privileged caller gets is the target for the restricted principal
    # once permitted below, rather than a hardcoded guess at that error.
    positive_code = _error(lambda: admin_ssm.get_access_token(AccessRequestId=bogus_id))["Code"]
    assert positive_code != "AccessDeniedException", (
        "a fully-privileged caller got AccessDeniedException too for the identical call "
        f"({positive_code!r}); the restricted principal's denial below would not be "
        "attributable to its missing IAM permission"
    )

    role_name = ctx.unique_name("sim2real-ssm-no-perms-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = ctx.unique_name("sim2real-session-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    restricted_ssm = ctx.client(
        "ssm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    denied = _error(lambda: restricted_ssm.get_access_token(AccessRequestId=bogus_id))
    assert denied["Code"] == "AccessDeniedException", denied
    assert denied["Message"] == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: ssm:GetAccessToken on resource: "
        f"arn:aws:ssm:{ctx.region}:{account_id}:opsitem/{bogus_id} because no "
        f"identity-based policy allows the ssm:GetAccessToken action"
    ), denied["Message"]

    policy_name = ctx.unique_name("sim2real-ssm-get-access-token-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ssm:GetAccessToken", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    restored_code = _poll_until(
        lambda: _error(lambda: restricted_ssm.get_access_token(AccessRequestId=bogus_id))["Code"],
        lambda c: c != "AccessDeniedException",
        timeout_s=90.0,
        description="the granted ssm:GetAccessToken permission becomes effective",
    )
    assert restored_code == positive_code, (
        f"after granting ssm:GetAccessToken, expected the identical error the fully-privileged "
        f"caller sees ({positive_code!r}), got {restored_code!r}"
    )


def _assume_role_with_retry(sts, role_arn, session_name, attempts=10, delay_s=2.0):
    """Retry AssumeRole until a new role is assumable; IAM trust propagation lags CreateRole."""
    last_exc = None
    for _ in range(attempts):
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
