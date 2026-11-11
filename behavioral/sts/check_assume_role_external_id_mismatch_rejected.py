"""assume-role-external-id-mismatch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-external-id-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A trust policy requiring sts:ExternalId refuses AssumeRole with a wrong or missing ExternalId
    as AccessDenied, while the correct ExternalId yields usable assumed-role credentials."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    correct_external_id = ctx.unique_name("sim2real-extid-correct-")
    role_name = ctx.unique_name("sim2real-extid-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"sts:ExternalId": correct_external_id}
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, role_name))

    # IAM trust propagation can lag a few seconds after CreateRole, so poll.
    control = _poll_until(
        lambda: _try_assume(sts, role_arn, "sim2real-extid-ctrl", correct_external_id),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert "Credentials" in control, f"expected Credentials in AssumeRole response, got {control!r}"
    _assert_usable_assumed_role_identity(
        ctx, control["Credentials"], account_id, role_name, "sim2real-extid-ctrl"
    )

    caller_arn = sts.get_caller_identity()["Arn"]
    denied = (
        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: "
        f"{role_arn}"
    )

    code, message = _refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sim2real-extid-wrong",
            ExternalId="definitely-not-the-right-one",
        )
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    assert message == denied, message

    code_again, message_again = _refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sim2real-extid-wrong2",
            ExternalId="definitely-not-the-right-one",
        )
    )
    assert code_again == "AccessDenied", f"expected AccessDenied, got {code_again!r}"
    assert message_again == denied, message_again

    code_missing, message_missing = _refusal(
        lambda: sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-extid-missing")
    )
    assert code_missing == "AccessDenied", f"expected AccessDenied, got {code_missing!r}"
    assert message_missing == denied, message_missing

    control_2 = sts.assume_role(
        RoleArn=role_arn, RoleSessionName="sim2real-extid-ctrl2", ExternalId=correct_external_id
    )
    assert "Credentials" in control_2, f"expected Credentials in AssumeRole response, got {control_2!r}"
    _assert_usable_assumed_role_identity(
        ctx, control_2["Credentials"], account_id, role_name, "sim2real-extid-ctrl2"
    )


def _assert_usable_assumed_role_identity(
    ctx, credentials, account_id, role_name, session_name
) -> None:
    """Require GetCallerIdentity through the credentials to return this role/session's ARN."""
    assumed_client = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretAccessKey"],
            "aws_session_token": credentials.get("SessionToken"),
        },
    )
    # Freshly issued credentials can briefly fail InvalidClientTokenId; poll.
    def _try_get_caller_identity():
        try:
            return assumed_client.get_caller_identity()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidClientTokenId":
                return None
            raise

    identity = _poll_until(
        _try_get_caller_identity, lambda r: r is not None, timeout_s=15.0, interval_s=2.0
    )
    expected_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    assert identity["Arn"] == expected_arn, (
        f"expected assumed-role identity {expected_arn!r}, got {identity['Arn']!r}"
    )
    assert identity["Account"] == account_id, (
        f"expected account {account_id!r}, got {identity['Account']!r}"
    )


def _try_assume(sts_client, role_arn, session_name, external_id):
    try:
        return sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName=session_name, ExternalId=external_id
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


def _refusal(fn):
    """(code, message) of the error ``fn`` raises; AssertionError when it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")

def _delete_role_if_exists(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
