"""assume-role-nonexistent-role-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-nonexistent-role-denied"
GROUP = 'overly-permissive'
SERVICES = ['sts']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRole on a well-formed but nonexistent role ARN is refused with AccessDenied (not
    NoSuchEntity, so role existence is not leaked), and succeeds once that role exists."""

    sts = ctx.client("sts")
    iam = ctx.client("iam")

    def _refusal(fn):
        """(code, message) of the error ``fn`` raises; AssertionError when it succeeds."""
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")

    def _account_id():
        return sts.get_caller_identity()["Account"]

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _wait_role_assumable(role_arn, timeout_s=120, interval_s=3.0):
        def probe():
            try:
                sts.assume_role(
                    RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-probe-")
                )
                return True
            except Exception:  # noqa: BLE001
                return False

        _poll_until(
            probe, lambda v: v is True, timeout_s=timeout_s, interval_s=interval_s,
            description=f"role {role_arn} became assumable",
        )

    account_id = _account_id()
    role_name = ctx.unique_name("sim2real-behav-no-such-role-")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    caller_arn = sts.get_caller_identity()["Arn"]

    code, message = _refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-")
        )
    )
    assert code == "AccessDenied", f"expected AccessDenied for a nonexistent role, got {code}"
    assert message == (
        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: "
        f"{role_arn}"
    ), message

    # Positive control: a target that denies EVERY AssumeRole would otherwise pass the denial
    # above. Create the exact role the ARN named and require the SAME RoleArn to succeed.
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
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )

    def _drop_role(role_name=role_name):
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_drop_role)

    _wait_role_assumable(role_arn)
    allowed = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-")
    )
    assert "Credentials" in allowed, allowed
    assert allowed["Credentials"].get("AccessKeyId"), allowed["Credentials"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
