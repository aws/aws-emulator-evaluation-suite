"""assume-role-foreign-account-role-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-foreign-account-role-denied"
GROUP = 'overly-permissive'
SERVICES = ['sts']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRole resolves a role by its full ARN including the account: our own assumable role,
    re-addressed under an unrelated account id, is denied with AccessDenied while the real ARN
    keeps working."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-foreign-acct-role-")
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
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, role_name))

    # IAM trust propagation can lag a few seconds after CreateRole, so poll.
    control = _poll_until(
        lambda: _try_assume(sts, role_arn, "sim2real-behav-ctrl"),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert "Credentials" in control, "positive control did not issue credentials"

    # Same role name under an unrelated account: no such role exists there, so it must be
    # denied even though the name resolves to an assumable role in our own account.
    foreign_arn = f"arn:aws:iam::111122223333:role/{role_name}"
    caller_arn = sts.get_caller_identity()["Arn"]
    code, message = _refusal(
        lambda: sts.assume_role(
            RoleArn=foreign_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-")
        )
    )
    assert code == "AccessDenied", (
        f"expected AccessDenied for a foreign-account role, got {code}"
    )
    assert message == (
        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: "
        f"{foreign_arn}"
    ), message

    # The denial is specific to the account segment; trust propagation is per replica, so poll.
    control_2 = _poll_until(
        lambda: _try_assume(sts, role_arn, ctx.unique_name("sim2real-behav-ctrl2-")),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert "Credentials" in control_2




def _try_assume(sts_client, role_arn, session_name):
    try:
        return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
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
