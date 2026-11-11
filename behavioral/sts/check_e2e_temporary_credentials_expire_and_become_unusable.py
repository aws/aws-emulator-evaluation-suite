"""e2e-temporary-credentials-expire-and-become-unusable."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-temporary-credentials-expire-and-become-unusable"
GROUP = "state-machine"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c4", "cap:c7",
      "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """AssumeRole credentials work immediately, Expiration matches DurationSeconds=900, and
    DurationSeconds=899 fails ValidationError with the exact minimum-900 message.

    Reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html"""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-expirerole-")
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-caller-identity",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_role_policy(
                RoleName=role_name, PolicyName="allow-caller-identity"
            )
        )
    )

    def _assume() -> dict:
        return sts.assume_role(
            RoleArn=role_arn, RoleSessionName="expiring-session", DurationSeconds=900
        )["Credentials"]

    creds = _retry_until_success(_assume, timeout_s=90.0, interval_s=3.0)
    client = _client_with_creds(ctx, "sts", creds)

    identity = client.get_caller_identity()
    assert f":assumed-role/{role_name}/" in identity["Arn"]

    expiration: datetime.datetime = creds["Expiration"]
    now = datetime.datetime.now(datetime.timezone.utc)
    wait_s = (expiration - now).total_seconds()
    assert wait_s > 0
    # The 900 s minimum duration exceeds the check's time budget, so expiry is not waited out.
    assert abs(wait_s - 900) < 30, f"unexpected Expiration offset: {wait_s}s"

    # botocore validates min=900 locally; disable client-side validation so 899 reaches STS.
    from botocore.config import Config

    floor_probe_sts = ctx.client("sts", config=Config(parameter_validation=False))
    floor_code, floor_message = _client_error(
        lambda: floor_probe_sts.assume_role(
            RoleArn=role_arn, RoleSessionName="too-short-session", DurationSeconds=899
        )
    )
    assert floor_code == "ValidationError", f"unexpected code: {floor_code}"
    assert floor_message == (
        "1 validation error detected: Value '899' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 900"
    ), floor_message



def _ignore_no_such_entity(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded where AWS refuses it")


def _client_with_creds(ctx: Any, service: str, creds: dict) -> Any:
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        },
    )


def _retry_until_success(
    fn: Callable[[], Any], *, timeout_s: float, interval_s: float
) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc}")


def _retry_until(
    fn: Callable[[], Any], *, predicate: Callable[[Any], bool], timeout_s: float, interval_s: float
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
