"""get-log-object-access-denied-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-log-object-access-denied-enforced"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A zero-permission role is denied DescribeLogGroups and refused on a malformed GetLogObject.

    Granting logs:DescribeLogGroups then makes the same call succeed.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    logs = ctx.client("logs")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-role-")
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
        Description="sim2real-behav: no-permission role for GetLogObject AccessDenied check",
        Tags=[{"Key": "Sim2RealOwner", "Value": "behavioral-suite"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = ctx.unique_name("sess-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    denied_logs = _client_with_creds(ctx, "logs", creds)

    # Control: proves the role genuinely blocks IAM-gated logs actions.
    control_code, control_message = _error(lambda: denied_logs.describe_log_groups(limit=1))
    assert control_code == "AccessDeniedException", (
        f"expected AccessDeniedException for DescribeLogGroups called by a "
        f"zero-permission principal (control for the GetLogObject assertion below), "
        f"got {control_code!r}"
    )
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: logs:DescribeLogGroups on resource: "
        f"arn:aws:logs:{ctx.region}:{account_id}:log-group::log-stream: because no "
        "identity-based policy allows the logs:DescribeLogGroups action"
    )
    assert control_message == expected_message, (
        f"expected message {expected_message!r}, got {control_message!r}"
    )

    # Pointer validation runs before authorization, so this identity gets the same
    # InvalidParameterException as a permissioned caller. GetLogObject's own IAM denial is not
    # observable: no genuine pointer can be minted. A seconds-old role can still read as
    # AccessDeniedException while IAM propagates, hence the bounded poll.
    code, message = _poll_for_error(
        lambda: denied_logs.get_log_object(logObjectPointer="sim2real-behav-dummy-pointer"),
        "InvalidParameterException",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for GetLogObject with no permissions and a "
        f"bogus pointer, got {code!r}"
    )
    expected_message = "Invalid log object pointer format."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Granting exactly the control's permission must make the identical call succeed.
    allow_policy_name = "allow-describe-log-groups"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=allow_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "logs:DescribeLogGroups", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=allow_policy_name)
    )
    restored_creds = _assume_role_with_retry(sts, role_arn, ctx.unique_name("sess-restored-"))
    restored_logs = _client_with_creds(ctx, "logs", restored_creds)
    _poll_for_success(
        lambda: restored_logs.describe_log_groups(limit=1), timeout_s=30.0, interval_s=2.0
    )


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_for_error(fn, expected_code: str, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _error(fn)
        if code == expected_code or time.monotonic() >= deadline:
            return code, message
        time.sleep(interval_s)


def _poll_for_success(fn, *, timeout_s: float, interval_s: float) -> None:
    """Retry across IAM's brief allow-policy propagation delay; raises if it never succeeds."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"restored call never succeeded within {timeout_s}s after granting permission: {last_err!r}"
    )


def _assume_role_with_retry(sts_client, role_arn, session_name, policy=None, timeout_s=45.0):
    """New IAM roles can take a few seconds to become assumable; retry through that window."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    kwargs = {"RoleArn": role_arn, "RoleSessionName": session_name}
    if policy is not None:
        kwargs["Policy"] = policy
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(**kwargs)["Credentials"]
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_err}")


def _client_with_creds(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
