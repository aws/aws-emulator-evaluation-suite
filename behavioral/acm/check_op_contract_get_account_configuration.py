"""op-contract-get-account-configuration."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-get-account-configuration"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountConfiguration returns a stable ExpiryEvents.DaysBeforeExpiry across calls, and a
    role with no policies is denied it with AccessDeniedException."""
    acm = ctx.client("acm")

    resp1 = acm.get_account_configuration()
    days1 = resp1["ExpiryEvents"]["DaysBeforeExpiry"]
    assert isinstance(days1, int) and days1 >= 1, f"expected an int >= 1, got {days1!r}"

    resp2 = acm.get_account_configuration()
    days2 = resp2["ExpiryEvents"]["DaysBeforeExpiry"]
    assert days2 == days1, "GetAccountConfiguration is not a stable read: value changed between calls"

    denied_acm, session_arn = _acm_client_for_permissionless_role(ctx)
    code, message = _error(lambda: denied_acm.get_account_configuration())
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected_message = (
        f"User: {session_arn} is not authorized to perform: acm:GetAccountConfiguration "
        "because no identity-based policy allows the acm:GetAccountConfiguration action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    resp3 = acm.get_account_configuration()
    assert resp3["ExpiryEvents"]["DaysBeforeExpiry"] == days1, (
        f"expected DaysBeforeExpiry to remain {days1}, got {resp3['ExpiryEvents']['DaysBeforeExpiry']}"
    )


def _error(fn):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}")


def _acm_client_for_permissionless_role(ctx):
    """An ACM client for a role with no policies, and that session's assumed-role ARN."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-acm-noperm-")
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": "get-account-configuration-contract"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    session_name = "sim2real-acm-noperm"
    deadline = time.monotonic() + 30.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name
            )["Credentials"]
            break
        except Exception as exc:  # role not yet assumable (propagation delay)
            last_exc = exc
            time.sleep(2.0)
    else:
        raise AssertionError(f"role never became assumable: {last_exc}")

    client = ctx.client(
        "acm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
