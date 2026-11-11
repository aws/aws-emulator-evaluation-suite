"""describe-agreement-missing-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-agreement-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["marketplace-agreement"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAgreement on a nonexistent agreement gets ResourceNotFoundException until an IAM Deny on
    the action makes it AccessDeniedException, and again after the Deny is detached, while an
    unrestricted caller keeps getting ResourceNotFoundException.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-mpa-deny-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    allow_policy_name = "allow-describe-agreement"
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "aws-marketplace:DescribeAgreement", "Resource": "*"}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=allow_policy_name, PolicyDocument=json.dumps(allow_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=allow_policy_name))

    fake_agreement_id = ctx.unique_name("sim2real-no-such-agreement-")
    not_found = ("ResourceNotFoundException", "Provided agreement does not exist.")
    creds = _poll_assume_role(sts, role["Arn"], timeout_s=60.0)
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    as_role = ctx.client(
        "marketplace-agreement",
        region="us-east-1",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # Positive control (same session, before any Deny exists): the granted role can already
    # make this exact call, and the only possible failure on a nonexistent id is not-found.
    before_code = _poll_until_code(
        lambda: _error_code(lambda: as_role.describe_agreement(agreementId=fake_agreement_id)),
        not_found,
        timeout_s=60.0,
    )
    assert before_code == not_found, (
        f"before any Deny is attached, the granted role's own call must only hit not-found, "
        f"got {before_code!r}"
    )

    # Break exactly one thing: an explicit Deny on the specific marketplace action.
    deny_policy_name = "deny-describe-agreement"
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "aws-marketplace:DescribeAgreement", "Resource": "*"}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=deny_policy_name, PolicyDocument=json.dumps(deny_policy)
    )
    ctx.on_cleanup(lambda: _delete_role_policy_if_present(iam, role_name, deny_policy_name))

    denied = (
        "AccessDeniedException",
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        "authorized to perform: aws-marketplace:DescribeAgreement on resource: * because no "
        "identity-based policy allows the aws-marketplace:DescribeAgreement or "
        "aws-marketplace:ViewSubscriptions action, or explicitly denies the actions",
    )
    denied_code = _poll_until_code(
        lambda: _error_code(lambda: as_role.describe_agreement(agreementId=fake_agreement_id)),
        denied,
        timeout_s=60.0,
    )
    assert denied_code == denied, f"expected {denied!r}, got {denied_code!r}"

    # Independent control at the same moment: the unrestricted caller identity makes the exact
    # same call and still only hits not-found, proving the Deny above -- not some account-wide
    # marketplace-agreement outage -- is what caused the denial.
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")
    control_code = _error_code(lambda: mpa.describe_agreement(agreementId=fake_agreement_id))
    assert control_code == not_found, f"expected {not_found!r}, got {control_code!r}"

    # Restore: remove the Deny and demand the IDENTICAL call, on the IDENTICAL session, returns
    # to the exact pre-Deny outcome -- proving the Deny (not the role, the session, or the fake
    # id) was the cause, and that its removal fully restores access.
    iam.delete_role_policy(RoleName=role_name, PolicyName=deny_policy_name)
    restored_code = _poll_until_code(
        lambda: _error_code(lambda: as_role.describe_agreement(agreementId=fake_agreement_id)),
        not_found,
        timeout_s=60.0,
    )
    assert restored_code == not_found, (
        f"removing the Deny must restore the identical call to the same not-found outcome as "
        f"before it was attached, got {restored_code!r}"
    )


_SESSION_NAME = "sim2real-mpa-deny-check"


def _error_code(fn):
    """The ClientError (code, message), or a raise."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _poll_until_code(fn, expected_code, timeout_s=60.0, interval_s=3.0):
    """IAM policy changes (attach or detach) are eventually consistent; poll the call until it
    settles on the expected (code, message), and raise -- never return the last, unsettled
    observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last == expected_code:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"expected {expected_code!r} within {timeout_s}s, last observed {last!r}")


def _delete_role_policy_if_present(iam, role_name, policy_name):
    """Cleanup-only: the body itself already deletes this policy as its restore beat, so
    cleanup must tolerate it already being gone."""
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_assume_role(sts_client, role_arn, timeout_s=60.0, interval_s=3.0):
    """IAM role trust propagation is eventually consistent; poll AssumeRole until it succeeds."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = sts_client.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )
            return resp["Credentials"]
        except ClientError as e:
            last_error = e
            time.sleep(interval_s)
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_error}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
