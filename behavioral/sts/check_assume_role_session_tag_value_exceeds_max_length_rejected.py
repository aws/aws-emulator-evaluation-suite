"""assume-role-session-tag-value-exceeds-max-length-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-session-tag-value-exceeds-max-length-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRole accepts a session tag value of exactly 256 characters and rejects 257 with
    ValidationError and the exact length-constraint message, on every retry."""
    iam = ctx.client("iam")
    sts_admin = ctx.client("sts")
    account_id = sts_admin.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-tagmax-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, role_name))

    # botocore enforces the 256-char limit client-side; disable local validation so the
    # over-length value actually reaches the service.
    sts = _client_no_validation(ctx, "sts")

    max_len_tags = [{"Key": "Team", "Value": "v" * 256}]
    over_len_tags = [{"Key": "Team", "Value": "v" * 257}]
    over_len_message = (
        f"1 validation error detected: Value '{'v' * 257}' at 'tags.1.member.value' failed to "
        "satisfy constraint: Member must have length less than or equal to 256"
    )

    # IAM trust propagation can lag a few seconds after CreateRole.
    control = _poll_until(
        lambda: _try_assume(sts, role_arn, "sim2real-tagmax-ctrl", max_len_tags),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert "Credentials" in control

    code, message = _error(
        lambda: sts.assume_role(
            RoleArn=role_arn, RoleSessionName="sim2real-tagmax-over", Tags=over_len_tags
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == over_len_message, message

    code_again, message_again = _error(
        lambda: sts.assume_role(
            RoleArn=role_arn, RoleSessionName="sim2real-tagmax-over2", Tags=over_len_tags
        )
    )
    assert code_again == "ValidationError", code_again
    assert message_again == over_len_message, message_again

    control_2 = sts.assume_role(
        RoleArn=role_arn, RoleSessionName="sim2real-tagmax-ctrl2", Tags=max_len_tags
    )
    assert "Credentials" in control_2

    # The minted credentials must be a usable identity, not just a response shape.
    creds = control_2["Credentials"]
    session_sts = ctx.client("sts", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    identity = session_sts.get_caller_identity()
    expected_arn_suffix = f":assumed-role/{role_name}/sim2real-tagmax-ctrl2"
    assert identity["Account"] == account_id, (
        f"expected the assumed session to resolve to account {account_id!r}, "
        f"got {identity['Account']!r}"
    )
    assert identity["Arn"].endswith(expected_arn_suffix), (
        f"expected the assumed session's identity ARN to end with "
        f"{expected_arn_suffix!r}, got {identity['Arn']!r}"
    )



def _client_no_validation(ctx, service: str):
    return ctx.client(service, config=Config(parameter_validation=False))


def _try_assume(sts_client, role_arn, session_name, tags):
    try:
        return sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName=session_name, Tags=tags
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AccessDenied":
            return None
        raise


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError("condition not met within timeout")
    return result


def _error(fn):
    """``(code, message)`` of the refusal ``fn()`` raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _delete_role_if_exists(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
