"""delete-retention-policy-without-permission-denied-leaves-value-intact."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-retention-policy-without-permission-denied-leaves-value-intact"
GROUP = "error-semantics"
SERVICES = ["logs", "iam", "sts"]

_DENIED = "AccessDeniedException"


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


def _retention_of(logs, group_name):
    groups = logs.describe_log_groups(logGroupNamePrefix=group_name).get("logGroups", [])
    by_name = {g["logGroupName"]: g for g in groups}
    return by_name.get(group_name, {}).get("retentionInDays")


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
    """A principal without logs:DeleteRetentionPolicy is denied the call and the log group's
    retention value is untouched; granting the action to the identical principal then lets the
    identical call succeed and clear it.
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-lg-delretpol-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=group), "ResourceNotFoundException"))

    logs.put_retention_policy(logGroupName=group, retentionInDays=14)
    baseline = _retention_of(logs, group)
    assert baseline == 14, f"expected the freshly-set retention to read back as 14, got {baseline!r}"

    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"

    role_name = ctx.unique_name("sim2real-behav-noretdel-")
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
    import json

    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav DeleteRetentionPolicy denial scenario",
        Tags=[{"Key": "sim2real", "Value": "delete-retention-policy-without-permission-denied"}],
    )

    def _delete_role(_n=role_name):
        for policy_name in iam.list_role_policies(RoleName=_n).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=_n, PolicyName=policy_name)
        iam.delete_role(RoleName=_n)

    ctx.on_cleanup(_delete_role)

    reader_policy_name = "sim2real-behav-read-only"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=reader_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        # logs:DeleteRetentionPolicy is ABSENT -- the one broken thing. There is
                        # no explicit Deny; the refusal below is IAM's implicit one.
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
                RoleSessionName="sim2real-behav-noretdel",
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
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/sim2real-behav-noretdel"

    def _control_attempt():
        try:
            return _retention_of(limited, group)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    # Positive control, which doubles as the bounded retry past IAM propagation: the same
    # principal, a call its inline policy DOES allow, must succeed before the denial means
    # anything about the missing action rather than about propagation.
    control = _poll_until(
        _control_attempt,
        lambda r: r == 14,
        description="the limited principal's read-only policy becomes effective",
    )
    assert control == 14, f"positive control: expected the limited read to see retentionInDays 14, got {control!r}"

    denied = (
        _DENIED,
        f"User: {session_arn} is not authorized to perform: logs:DeleteRetentionPolicy on resource: "
        f"{group_arn} because no identity-based policy allows the logs:DeleteRetentionPolicy action",
    )
    expect_error(lambda: limited.delete_retention_policy(logGroupName=group), *denied)

    # The forbidden effect did not happen: an independent read (through the original,
    # unrestricted client) still finds the retention value set.
    after_denial = _retention_of(logs, group)
    assert after_denial == 14, (
        f"the denied DeleteRetentionPolicy call must not have cleared retentionInDays, got {after_denial!r}"
    )

    # Restore, on the SAME denied principal: grant logs:DeleteRetentionPolicy to the identical
    # role and re-issue the identical call.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-grant-delete-retention",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "logs:DeleteRetentionPolicy",
                        "Resource": [group_arn, f"{group_arn}:*"],
                    }
                ],
            }
        ),
    )

    def _delete_attempt():
        try:
            limited.delete_retention_policy(logGroupName=group)
            return "done"
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    _poll_until(
        _delete_attempt,
        lambda r: r == "done",
        timeout_s=180.0,
        description="the identical DeleteRetentionPolicy call succeeds once the grant propagates",
    )

    cleared = _retention_of(logs, group)
    assert cleared is None, f"expected retentionInDays to be cleared after the permitted delete, got {cleared!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
