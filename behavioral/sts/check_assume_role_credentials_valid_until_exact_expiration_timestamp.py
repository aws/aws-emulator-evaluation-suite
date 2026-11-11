"""assume-role-credentials-valid-until-exact-expiration-timestamp."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-credentials-valid-until-exact-expiration-timestamp"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssumeRole credentials work immediately, Expiration is issue time + DurationSeconds, and the
    service itself rejects a DurationSeconds below the 900s floor rather than clamping it.

    Reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="perm",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="perm"))
    _warm_up_assume_role(ctx, role_arn)

    before = datetime.now(timezone.utc)
    resp = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=ctx.unique_name("sess-ttl-"), DurationSeconds=900
    )
    after = datetime.now(timezone.utc)
    creds = resp["Credentials"]
    expiration = creds["Expiration"]
    session_sts = _client_with_creds(ctx, "sts", creds)

    identity = session_sts.get_caller_identity()
    assert identity["Arn"] == resp["AssumedRoleUser"]["Arn"], (
        f"expected assumed-role ARN {resp['AssumedRoleUser']['Arn']!r}, "
        f"got {identity['Arn']!r}"
    )

    # Waiting out the 900s minimum window does not fit the check's time budget, so the window
    # bound is checked via the exact Expiration value plus enforcement of the floor below.
    assert before.timestamp() + 900 - 5 <= expiration.timestamp() <= after.timestamp() + 900 + 5, (
        f"Expiration {expiration} is not requested-duration-900s from the issuance "
        f"window [{before}, {after}]"
    )

    # Parameter validation is off so DurationSeconds=899 reaches the service; botocore's own
    # shape range would otherwise reject it locally against any target.
    unvalidated_sts = ctx.client("sts", config=Config(parameter_validation=False))
    floor_code, floor_message = _refusal(
        lambda: unvalidated_sts.assume_role(
            RoleArn=role_arn, RoleSessionName="too-short-session", DurationSeconds=899
        )
    )
    assert floor_code == "ValidationError", (
        f"expected the floor to be enforced with ValidationError, got {floor_code!r}"
    )
    assert floor_message == (
        "1 validation error detected: Value '899' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 900"
    ), floor_message



def _warm_up_assume_role(ctx, role_arn: str, timeout_s: float = 45.0, interval_s: float = 3.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="warmup")["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_exc}")


def _client_with_creds(ctx, service: str, creds: dict):
    return ctx.client(
        service,
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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
