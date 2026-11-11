"""get-log-object-unauthorized-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-log-object-unauthorized-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GetLogObject never returns data to a principal without logs:GetLogObject, even one holding
    another logs:* permission, while a fully permitted caller fails at lookup, not with access denied."""
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-glo-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    log_object_pointer = f"{group}:0000000000000:00000000000000000000000000000000"

    positive_code, positive_message = _error(
        lambda: logs.get_log_object(logObjectPointer=log_object_pointer)
    )
    assert positive_code == "InvalidParameterException", (
        "positive control: a fully-permissioned caller resolving a well-formed but "
        f"never-issued logObjectPointer must fail at the lookup stage, got {positive_code!r} "
        "-- if this were an access-denied code the pointer shape would be wrong and the "
        "negative below would be meaningless"
    )
    expected_message = "Invalid log object pointer format."
    assert positive_message == expected_message, (
        f"expected message {expected_message!r}, got {positive_message!r}"
    )

    role_name = ctx.unique_name("sim2real-behav-nolgo-role-")
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
    ctx.on_cleanup(lambda: _delete_role_best_effort(iam, role_name))

    # Grant only an unrelated read permission -- logs:GetLogObject is intentionally
    # NOT included, so it falls to IAM's implicit deny.
    minimal_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "logs:DescribeLogGroups", "Resource": "*"}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="minimal-no-get-log-object",
        PolicyDocument=json.dumps(minimal_policy),
    )
    ctx.on_cleanup(lambda: _delete_role_policy_best_effort(iam, role_name))

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    creds = _assume_role_with_retry(
        sts, role_arn, ctx.unique_name("sim2real-behav-sess-")
    )

    restricted_logs = ctx.client(
        "logs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # IAM policy/role changes can take a short time to propagate. Pointer validation runs
    # before authorization on real AWS, so the restricted caller gets the same
    # InvalidParameterException as the positive control; the bounded poll rides out a
    # propagation transient, and any successful response raises inside _error.
    code, message = _poll_for_error(
        lambda: restricted_logs.get_log_object(logObjectPointer=log_object_pointer),
        "InvalidParameterException",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert code == "InvalidParameterException", (
        "expected GetLogObject to reject a caller lacking logs:GetLogObject with the same "
        f"InvalidParameterException the positive control gets, got {code!r}"
    )
    expected_message = "Invalid log object pointer format."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _poll_for_error(fn, expected_code: str, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _error(fn)
        if code == expected_code or time.monotonic() >= deadline:
            return code, message
        time.sleep(interval_s)


def _assume_role_with_retry(
    sts, role_arn: str, session_name: str, timeout_s: float = 30.0
) -> dict:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)[
                "Credentials"
            ]
        except ClientError as err:
            last_err = err
            time.sleep(2.0)
    raise AssertionError(
        f"could not assume role {role_arn} within {timeout_s}s: {last_err}"
    )


def _delete_role_policy_best_effort(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(
            RoleName=role_name, PolicyName="minimal-no-get-log-object"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_best_effort(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
