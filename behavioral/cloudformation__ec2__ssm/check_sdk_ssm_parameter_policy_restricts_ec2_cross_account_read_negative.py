"""sdk-ssm-parameter-policy-restricts-ec2-cross-account-read-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sdk-ssm-parameter-policy-restricts-ec2-cross-account-read-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A caller on assumed-role credentials whose identity policy denies ssm:GetParameter* gets
    AccessDeniedException with the exact explicit-deny message and no value; removing only the deny
    lets the same credentials read the value again."""
    ssm = ctx.client("ssm")
    param_name = ctx.unique_name("/sim2real/restricted-")
    value = ctx.unique_name("sim2real-value-")
    ssm.put_parameter(
        Name=param_name,
        Value=value,
        Type="String",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))

    # positive control, before anything is denied: an unrestricted caller reads back the
    # value it just wrote.
    control = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert control == value, (
        f"the unrestricted caller must read back the value it just wrote; expected "
        f"{value!r}, got {control!r}"
    )

    deny_actions = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
    denied_ssm, restore_access, session_arn = _client_with_deny_policy(ctx, "ssm", deny_actions)

    resource_arn = f"arn:aws:ssm:{ctx.region}:{ctx.account}:parameter{param_name}"
    expected_message = (
        f"User: {session_arn} is not authorized to perform: ssm:GetParameter on resource: "
        f"{resource_arn} with an explicit deny in an identity-based policy"
    )
    # Until the fresh role policy propagates, AWS refuses with the implicit-deny message
    # ("no identity-based policy allows"); poll, bounded, until the explicit Deny decides.
    implicit_message = (
        f"User: {session_arn} is not authorized to perform: ssm:GetParameter on resource: "
        f"{resource_arn} because no identity-based policy allows the ssm:GetParameter action"
    )
    deadline = time.monotonic() + 60.0
    while True:
        code, message = _error(lambda: denied_ssm.get_parameter(Name=param_name))
        if message != implicit_message or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    assert code == "AccessDeniedException", (
        f"a caller whose identity policy explicitly denies {deny_actions} must be refused "
        f"GetParameter with AccessDeniedException; got {code!r}"
    )
    assert message == expected_message, f"unexpected AccessDeniedException message: {message!r}"

    # restore: lift the deny on the SAME assumed-role credentials and demand the identical
    # call succeeds, proving the deny -- not something else -- was blocking it.
    restore_access()
    restored = _poll_until_success(
        lambda: denied_ssm.get_parameter(Name=param_name)["Parameter"]["Value"],
        timeout_s=30.0,
        description="GetParameter succeeds again on the same credentials after the deny is lifted",
    )
    assert restored == value, (
        f"lifting the deny statement must restore GetParameter on the identical "
        f"assumed-role credentials; expected {value!r}, got {restored!r}"
    )


def _client_with_deny_policy(ctx, service: str, deny_actions: list[str]):
    """Assume a fresh role, trusted the way an EC2 instance role would be as well as by
    the account root (so this script can assume it directly), that allows everything
    except `deny_actions` (explicit Deny always wins over Allow). Returns the client built
    on that role's credentials, a `restore()` callable that overwrites the role policy
    to drop the Deny statement -- for the negative's restore beat -- without touching the
    assumed credentials, and the assumed-role session ARN."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-deny-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"},
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    allow_only_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    deny_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": deny_actions, "Resource": "*"},
        ],
    }
    policy_name = ctx.unique_name("sim2real-deny-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(deny_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    # IAM role propagation is eventually consistent; poll assume-role until it succeeds.
    deadline = time.monotonic() + 30.0
    creds = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-check")["Credentials"]
            break
        except ClientError:
            time.sleep(2.0)
    if creds is None:
        raise AssertionError(f"could not assume role {role_arn} in time")

    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-check"

    def restore():
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(allow_only_doc)
        )

    return client, restore, session_arn


def _poll_until_success(fn, *, timeout_s: float, interval_s: float = 2.0, description: str = "condition"):
    """Retry `fn()` until it stops raising `ClientError`, for the eventual consistency of an
    IAM policy change. Raises on timeout -- never returns a stale/last value."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last error {last_code!r}")


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    over-permissive target is reported as accepting the call, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
