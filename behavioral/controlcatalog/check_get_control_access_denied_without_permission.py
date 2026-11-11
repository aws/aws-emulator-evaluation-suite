"""get-control-access-denied-without-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-control-access-denied-without-permission"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_SESSION_NAME = "sim2real-cc-check"
_DENY_MESSAGE = (
    "User: {principal} is not authorized to perform: controlcatalog:GetControl on resource: {control} "
    "because no identity-based policy allows the controlcatalog:GetControl action"
)


@tags("axis:rejection", "cap:c5", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IAM principal with no attached permissions cannot call controlcatalog:GetControl."""
    cc = ctx.client("controlcatalog")
    real_arn = cc.list_controls(MaxResults=1)["Controls"][0]["Arn"]

    creds, account_id, role_name = _create_unprivileged_role_and_assume(ctx)
    # Same target as ctx.client(); only the credentials differ for the restricted principal.
    denied_client = ctx.client(
        "controlcatalog",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    code, message = _error_code(lambda: denied_client.get_control(ControlArn=real_arn))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for an unprivileged assumed role, got {code!r}"
    )
    expected = _DENY_MESSAGE.format(
        principal=f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}", control=real_arn
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # positive control: the caller's own (permitted) credentials still succeed
    detail = cc.get_control(ControlArn=real_arn)
    assert detail["Arn"] == real_arn, (
        f"expected the permitted caller's get_control to return {real_arn!r}, got {detail.get('Arn')!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}"
    )


def _create_unprivileged_role_and_assume(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-cc-noperm-")
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
        Tags=[{"Key": "sim2real", "Value": "get-control-access-denied-without-permission"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    # Newly created IAM roles take a few seconds to become assumable account-wide; poll for that.
    deadline = time.monotonic() + 30.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)
            return resp["Credentials"], account_id, role_name
        except ClientError as exc:
            last_error = exc
            time.sleep(2.0)
    raise AssertionError(f"could not assume newly created role within timeout: {last_error}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
