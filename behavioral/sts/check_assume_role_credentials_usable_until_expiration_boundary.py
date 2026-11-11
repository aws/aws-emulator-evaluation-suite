"""assume-role-credentials-usable-until-expiration-boundary."""
from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-credentials-usable-until-expiration-boundary"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """AssumeRole credentials keep authenticating across a 10s window, a second AssumeRole gets
    its own later Expiration, and a DurationSeconds above the 43200s ceiling is rejected by the
    service rather than clamped."""
    role_arn = _create_assumable_role(ctx)
    sts = ctx.client("sts")
    resp = _assume_role_tolerating_propagation_lag(
        sts, RoleArn=role_arn, RoleSessionName=ctx.unique_name("behav-sess-")[:64],
        DurationSeconds=900,
    )
    issued_at = time.monotonic()
    creds = resp["Credentials"]
    assumed_arn = resp["AssumedRoleUser"]["Arn"]
    expiration: datetime = creds["Expiration"]
    role_client = _sts_client_with_creds(ctx, creds)

    identity_early = role_client.get_caller_identity()
    assert identity_early["Arn"] == assumed_arn, (
        f"assumed-role credentials authenticated as {identity_early['Arn']!r}, expected "
        f"{assumed_arn!r}"
    )

    # Waiting out the 900s minimum window does not fit the check's time budget, so this
    # polls a bounded window instead: the same credentials must authenticate at every poll.
    window_end = issued_at + 10
    while True:
        identity_mid = role_client.get_caller_identity()
        assert identity_mid["Arn"] == assumed_arn, (
            f"assumed-role credentials stopped authenticating as {assumed_arn!r}, got "
            f"{identity_mid['Arn']!r}"
        )
        assert identity_mid["Account"] == identity_early["Account"], (
            f"account changed mid-window: {identity_early['Account']!r} -> "
            f"{identity_mid['Account']!r}"
        )
        if time.monotonic() >= window_end:
            break
        time.sleep(2)

    creds_again = _assume_role_tolerating_propagation_lag(
        sts, RoleArn=role_arn, RoleSessionName=ctx.unique_name("behav-sess-")[:64],
        DurationSeconds=900,
    )["Credentials"]
    between_s = time.monotonic() - issued_at
    # Each AssumeRole gets its own window, not one capped by an earlier session's expiration,
    # and its Expiration moves by no more than the time that passed between the two calls.
    advanced = (creds_again["Expiration"] - expiration).total_seconds()
    assert 1 <= advanced <= between_s + 2, (
        f"a second AssumeRole issued {between_s:.0f}s later must expire that much later, got "
        f"{advanced:.1f}s ({expiration} -> {creds_again['Expiration']})"
    )

    # Parameter validation is off so the request reaches the service; botocore's own shape
    # constraint (max=43200) would otherwise reject it locally against any target.
    unvalidated_sts = ctx.client("sts", config=Config(parameter_validation=False))
    error = _client_error(lambda: unvalidated_sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("behav-sess-")[:64],
        DurationSeconds=999999,
    ))
    assert error == (
        "ValidationError",
        "1 validation error detected: Value '999999' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value less than or equal to 43200",
    ), error




def _create_assumable_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    role_name = ctx.unique_name("sim2real-behav-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    _assume_role_tolerating_propagation_lag(
        sts, RoleArn=role_arn, RoleSessionName="probe", DurationSeconds=900,
    )
    return role_arn


def _assume_role_tolerating_propagation_lag(sts, timeout_s: float = 30.0, **kwargs):
    """AssumeRole, retrying only AccessDenied while trust-policy propagation settles.

    Propagation is not monotonic: one AssumeRole can succeed and the next still be denied."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"AssumeRole still denied after {timeout_s}s of propagation: {last_exc}")


def _sts_client_with_creds(ctx: Any, creds: dict) -> Any:
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _client_error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises; AssertionError when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call succeeded; expected a service-side rejection")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

