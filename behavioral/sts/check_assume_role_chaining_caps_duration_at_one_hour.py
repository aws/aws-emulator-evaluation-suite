"""assume-role-chaining-caps-duration-at-one-hour."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-chaining-caps-duration-at-one-hour"
GROUP = 'error-semantics'
SERVICES = ['sts']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A chained AssumeRole asking 7200s is refused ValidationError even though the role allows 2h;
    a 3600s chained session succeeds and its credentials resolve to the target role."""

    sts = ctx.client("sts")

    def _client_with_credentials(service, creds):
        return ctx.client(
            service,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds.get("SessionToken"),
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

    def _stable_refusal(fn, transient=(), attempts=8, interval_s=3.0):
        """``_refusal`` retried while its code is one of ``transient``."""
        last = None
        for _ in range(attempts):
            last = _refusal(fn)
            if last[0] not in transient:
                return last
            time.sleep(interval_s)
        return last

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _retry_until_token_valid(fn, timeout_s=60, interval_s=2.0):
        transient = ("InvalidClientTokenId", "AccessDenied", "InvalidAccessKeyId")
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001
                response = getattr(exc, "response", None)
                code = response.get("Error", {}).get("Code") if response else None
                if code not in transient or time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)

    def _wait_creds_active(creds, service="sts"):
        probe = _client_with_credentials(service, creds)

        def _active():
            try:
                probe.get_caller_identity()
            except ClientError:
                return False
            return True

        _poll_until(
            _active, lambda ok: ok is True, timeout_s=60, interval_s=2.0,
            description="temporary credentials became active",
        )

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

    def _wait_role_assumable(role_arn, assume_kwargs=None, timeout_s=120, interval_s=3.0):
        kwargs = dict(assume_kwargs or {})

        def probe():
            try:
                sts.assume_role(
                    RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-probe-"), **kwargs
                )
                return True
            except Exception:  # noqa: BLE001
                return False

        _poll_until(
            probe, lambda v: v is True, timeout_s=timeout_s, interval_s=interval_s,
            description=f"role {role_arn} became assumable",
        )

    def _create_assumable_role(trust_policy=None, max_session_duration=3600, inline_policy=None,
                               assume_kwargs=None):
        role_name = ctx.unique_name("sim2real-behav-sts-role-")
        policy = trust_policy if trust_policy is not None else _default_trust_policy()
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(policy),
            MaxSessionDuration=max_session_duration,
            Tags=_tags_kv(),
        )

        def _drop_role(role_name=role_name):
            try:
                for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                    try:
                        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "NoSuchEntity":
                            raise
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
            try:
                iam.delete_role(RoleName=role_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_drop_role)
        role_arn = resp["Role"]["Arn"]
        if inline_policy is not None:
            iam.put_role_policy(
                RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
            )
        _wait_role_assumable(role_arn, assume_kwargs=assume_kwargs)
        return role_name, role_arn

    iam = ctx.client("iam")

    account = _account_id()
    # Role A: assumable by the account principal, allowed to assume anything.
    a_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["sts:AssumeRole", "sts:GetCallerIdentity"], "Resource": "*"}
        ],
    }
    _a_name, a_arn = _create_assumable_role(inline_policy=a_policy)
    # Role B: 2h max session, assumable by anyone in the account (incl. role A).
    b_name, b_arn = _create_assumable_role(max_session_duration=7200)

    first = sts.assume_role(RoleArn=a_arn, RoleSessionName=ctx.unique_name("sim2real-behav-chain-a-"))
    _wait_creds_active(first["Credentials"])
    client = _client_with_credentials("sts", first["Credentials"])

    session_b = ctx.unique_name("sim2real-behav-chain-b-")

    # A 2h chained session is refused (1h ceiling for role chaining).
    code, message = _stable_refusal(
        lambda: client.assume_role(RoleArn=b_arn, RoleSessionName=session_b, DurationSeconds=7200),
        transient=("AccessDenied", "InvalidClientTokenId"),
    )
    assert code == "ValidationError", code
    assert message == (
        "The requested DurationSeconds exceeds the 1 hour session limit for roles assumed by "
        "role chaining."
    ), message

    # ...but a 1h chained session works, and the identity reflects role B.
    chained = _retry_until_token_valid(
        lambda: client.assume_role(RoleArn=b_arn, RoleSessionName=session_b, DurationSeconds=3600)
    )
    expected_arn = f"arn:aws:sts::{account}:assumed-role/{b_name}/{session_b}"
    assert chained["AssumedRoleUser"]["Arn"] == expected_arn, chained["AssumedRoleUser"]

    chained_client = _client_with_credentials("sts", chained["Credentials"])
    _wait_creds_active(chained["Credentials"])
    whoami = chained_client.get_caller_identity()
    assert whoami["Arn"] == expected_arn, (expected_arn, whoami)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
