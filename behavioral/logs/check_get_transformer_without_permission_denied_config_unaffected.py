"""get-transformer-without-permission-denied-config-unaffected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-transformer-without-permission-denied-config-unaffected"
GROUP = "error-semantics"
SERVICES = ["logs", "iam", "sts"]

_DENIED = "AccessDeniedException"

_TRANSFORMER_CONFIG = [
    {"parseJSON": {}},
    {
        "addKeys": {
            "entries": [
                {"key": "sim2real_marker", "value": "get-transformer-denial-probe", "overwriteIfExists": True}
            ]
        }
    },
]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, unless it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code, message):
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected ({code!r}, {message!r}), but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last value: {last!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal without logs:GetTransformer is denied the call and never sees the attached
    transformer's configuration; granting the action to the identical principal then lets the
    identical call succeed and return the exact config, unmodified by the earlier denial.
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-lg-notransget-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=group), "ResourceNotFoundException"))
    ctx.on_cleanup(
        _teardown(lambda: logs.delete_transformer(logGroupIdentifier=group), "ResourceNotFoundException")
    )

    logs.put_transformer(logGroupIdentifier=group, transformerConfig=_TRANSFORMER_CONFIG)
    baseline = logs.get_transformer(logGroupIdentifier=group)["transformerConfig"]
    assert baseline == _TRANSFORMER_CONFIG, f"expected the config just put, got {baseline!r}"

    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"

    role_name = ctx.unique_name("sim2real-behav-notransget-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav GetTransformer denial scenario",
        Tags=[{"Key": "sim2real", "Value": "get-transformer-without-permission-denied"}],
    )

    def _delete_role(_n=role_name):
        for policy_name in iam.list_role_policies(RoleName=_n).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=_n, PolicyName=policy_name)
        iam.delete_role(RoleName=_n)

    ctx.on_cleanup(_delete_role)

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-read-only",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        # logs:GetTransformer is ABSENT -- the one broken thing. There is no
                        # explicit Deny; the refusal below is IAM's implicit one.
                        "Effect": "Allow",
                        "Action": "logs:DescribeLogGroups",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    deadline = time.monotonic() + 60.0
    creds = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=f"arn:aws:iam::{account}:role/{role_name}",
                RoleSessionName="sim2real-behav-notransget",
            )["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3.0)
    assert creds is not None, (
        f"AssumeRole on the freshly-created role {role_name!r} never succeeded within 60s: {last_exc!r}"
    )

    limited = ctx.client(
        "logs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/sim2real-behav-notransget"

    def _control_attempt():
        try:
            limited.describe_log_groups(logGroupNamePrefix=group)
            return "done"
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    # Positive control, which doubles as the bounded retry past IAM propagation: the same
    # principal, a call its inline policy DOES allow, must succeed before the denial means
    # anything about the missing action rather than about propagation.
    _poll_until(
        _control_attempt,
        lambda r: r == "done",
        description="the limited principal's read-only policy becomes effective",
    )

    denied = (
        _DENIED,
        f"User: {session_arn} is not authorized to perform: logs:GetTransformer on resource: "
        f"{group_arn} because no identity-based policy allows the logs:GetTransformer action",
    )
    expect_error(lambda: limited.get_transformer(logGroupIdentifier=group), *denied)

    # The forbidden effect did not happen: an independent read (through the original,
    # unrestricted client) still finds the exact config the denied principal never saw.
    after_denial = logs.get_transformer(logGroupIdentifier=group)["transformerConfig"]
    assert after_denial == _TRANSFORMER_CONFIG, (
        f"the denied GetTransformer call must not have altered the stored config, got {after_denial!r}"
    )

    # Restore, on the SAME denied principal: grant logs:GetTransformer to the identical role
    # and re-issue the identical call.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-grant-get-transformer",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "logs:GetTransformer",
                        "Resource": [group_arn, f"{group_arn}:*"],
                    }
                ],
            }
        ),
    )

    def _get_attempt():
        try:
            return limited.get_transformer(logGroupIdentifier=group)["transformerConfig"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    granted = _poll_until(
        _get_attempt,
        lambda r: r == _TRANSFORMER_CONFIG,
        timeout_s=180.0,
        description="the identical GetTransformer call succeeds once the grant propagates",
    )
    assert granted == _TRANSFORMER_CONFIG, (
        f"a caller WITH logs:GetTransformer must recover the exact config, got {granted!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
