"""assume-role-credentials-expiration-anchored-to-requested-duration."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-credentials-expiration-anchored-to-requested-duration"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """AssumeRole credentials authenticate as the assumed role, Expiration is issue-time + the
    requested 900s, and DurationSeconds=500 (below the 900s floor) is refused ValidationError."""
    role_arn = _create_assumable_role(ctx)
    sts = ctx.client("sts")

    # Trust-policy propagation can still give a transient AccessDenied after the setup probe
    # succeeded; before/after bracket the attempt that succeeds so the TTL anchor stays precise.
    before, after, resp = _assume_role_until_propagated(
        sts, role_arn, ctx.unique_name("behav-sess-")[:64]
    )
    creds = resp["Credentials"]
    assumed_arn = resp["AssumedRoleUser"]["Arn"]
    role_client = _sts_client_with_creds(ctx, creds)

    # A brand-new session token can briefly lag propagation, so poll.
    identity = _wait_for_new_credentials(role_client)
    assert identity["Arn"] == assumed_arn, (
        f"assumed-role credentials authenticated as {identity['Arn']!r}, expected {assumed_arn!r}"
    )

    expiration = creds["Expiration"]
    assert before.timestamp() + 900 - 5 <= expiration.timestamp() <= after.timestamp() + 900 + 5, (
        f"Expiration {expiration} is not requested-duration-900s from issuance "
        f"window [{before}, {after}]"
    )

    # botocore enforces DurationSeconds min=900 client-side, so validation is turned off to
    # let the service answer the below-floor request.
    unvalidated = _unvalidated_sts_client(ctx)
    code, message = _refusal(lambda: unvalidated.assume_role(
        RoleArn=role_arn, RoleSessionName=ctx.unique_name("behav-sess-")[:64], DurationSeconds=500
    ))
    assert code == "ValidationError", f"unexpected code: {code}"
    assert message == (
        "1 validation error detected: Value '500' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 900"
    ), message


def _create_assumable_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
    role_name = ctx.unique_name("sim2real-behav-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": caller_arn}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    # IAM trust-policy propagation is eventually consistent; poll AssumeRole itself.
    deadline = time.monotonic() + 30
    last_code: str | None = None
    while time.monotonic() < deadline:
        try:
            sts.assume_role(RoleArn=role_arn, RoleSessionName="probe", DurationSeconds=900)
            return role_arn
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            time.sleep(2)
    raise AssertionError(f"role never became assumable within 30s (last_code={last_code})")


def _assume_role_until_propagated(
    sts_client: Any, role_arn: str, session_name: str, timeout_s: float = 20.0, interval_s: float = 2.0
):
    """Retry AssumeRole until trust-policy propagation catches up; return (before, after, response)
    bracketing the attempt that succeeded."""
    deadline = time.monotonic() + timeout_s
    last_code: str | None = None
    while True:
        before = datetime.now(timezone.utc)
        try:
            resp = sts_client.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=900
            )
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"AssumeRole on a role whose trust policy already allows this caller never "
                    f"propagated within {timeout_s}s (last_code={last_code})"
                ) from exc
            time.sleep(interval_s)
            continue
        after = datetime.now(timezone.utc)
        return before, after, resp


def _unvalidated_sts_client(ctx: Any) -> Any:
    # Client-side parameter validation off, so the SERVICE's own input validation answers
    # instead of a local ParamValidationError.
    return ctx.client(
        "sts", config=Config(retries={"max_attempts": 1}, parameter_validation=False)
    )


def _sts_client_with_creds(ctx: Any, creds: dict) -> Any:
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _refusal(fn):
    """(code, message) of the error ``fn`` raises; AssertionError when it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")

def _wait_for_new_credentials(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0):
    """Poll GetCallerIdentity until a brand-new session token stops failing InvalidClientTokenId."""
    deadline = time.monotonic() + timeout_s
    last_err: str | None = None
    while time.monotonic() < deadline:
        try:
            return sts_client.get_caller_identity()
        except ClientError as exc:
            last_err = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(f"new credentials never became valid within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

