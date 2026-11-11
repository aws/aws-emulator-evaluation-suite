"""assume-role-default-duration-is-one-hour."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "assume-role-default-duration-is-one-hour"
GROUP = 'credential-issuance'
SERVICES = ['sts']


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssumeRole without DurationSeconds issues credentials that authenticate as the assumed role
    and expire 3600s after issuance, not at the role's 7200s MaxSessionDuration."""

    sts = ctx.client("sts")

    def _session_client(creds):
        return ctx.client(
            "sts",
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            },
        )

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _account_id():
        return sts.get_caller_identity()["Account"]

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _default_trust_policy():
        # Trust the current account root for the three session actions we exercise.
        account_id = _account_id()
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                }
            ],
        }

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

    def _create_assumable_role(max_session_duration):
        role_name = ctx.unique_name("sim2real-behav-sts-role-")
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(_default_trust_policy()),
            MaxSessionDuration=max_session_duration,
            Tags=_tags_kv(),
        )

        def _drop_role(role_name=role_name):
            try:
                iam.delete_role(RoleName=role_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_drop_role)
        role_arn = resp["Role"]["Arn"]
        _wait_role_assumable(role_arn)
        return role_name, role_arn

    def _identity_or_none(client):
        try:
            return client.get_caller_identity()
        except Exception:  # noqa: BLE001
            return None

    iam = ctx.client("iam")

    _role_name, role_arn = _create_assumable_role(max_session_duration=7200)
    session_name = ctx.unique_name("sim2real-behav-sess-")

    before = datetime.datetime.now(datetime.timezone.utc)
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    after = datetime.datetime.now(datetime.timezone.utc)
    creds = resp["Credentials"]
    assumed_arn = resp["AssumedRoleUser"]["Arn"]

    # A brand-new session token can lag propagation by a beat.
    session_sts = _session_client(creds)
    identity = _poll_until(
        lambda: _identity_or_none(session_sts), lambda v: v is not None,
        timeout_s=30, interval_s=2.0, description="assumed credentials became usable",
    )
    assert identity["Arn"] == assumed_arn, f"expected {assumed_arn}, got {identity['Arn']}"

    expiration = creds["Expiration"]
    assert before.timestamp() + 3600 - 5 <= expiration.timestamp() <= after.timestamp() + 3600 + 5, (
        f"expected an Expiration 3600s past issuance window [{before}, {after}], got {expiration}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
