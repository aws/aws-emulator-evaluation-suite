"""assume-role-session-policy-over-max-length-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "assume-role-session-policy-over-max-length-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A session Policy longer than the 2048-character plain-text limit is a ValidationError.

    The raw length limit is enforced (ValidationError) BEFORE any packing occurs,
    so an oversized document never reaches the PackedPolicyTooLarge path."""

    sts = ctx.client("sts")

    def _make_client_for(service):
        return ctx.client(service)

    def _client_with_credentials(service, creds):
        return ctx.client(service, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    def _error_code(fn):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            if response is not None:
                return response.get("Error", {}).get("Code"), response.get("Error", {}).get("Message")
            return type(exc).__name__, str(exc)
        return _OK, None

    def _stable_error_code(fn, transient=(), attempts=8, interval_s=3.0):
        last = (None, None)
        for _ in range(attempts):
            last = _error_code(fn)
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
            # NoSuchEntity means the role or policy is already gone; anything else is a real failure.
            try:
                for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                    try:
                        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
                    except iam.exceptions.NoSuchEntityException:
                        pass
                iam.delete_role(RoleName=role_name)
            except iam.exceptions.NoSuchEntityException:
                pass

        ctx.on_cleanup(_drop_role)
        role_arn = resp["Role"]["Arn"]
        if inline_policy is not None:
            iam.put_role_policy(
                RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
            )
        _wait_role_assumable(role_arn, assume_kwargs=assume_kwargs)
        return role_name, role_arn

    def _oversized_session_policy():
        # Syntactically valid policy whose plain-text length exceeds the 2048-char limit.
        return json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject",
                 "Resource": f"arn:aws:s3:::sim2real-behav-{'x' * 2200}/*"}
            ],
        })

    def _valid_session_policy():
        # Same shape as the oversized policy but comfortably under the 2048-char limit --
        # the positive control that isolates the rejection to SIZE, not to the Policy
        # parameter itself.
        return json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject",
                 "Resource": "arn:aws:s3:::sim2real-behav-control/*"}
            ],
        })

    iam = _make_client_for("iam")

    _role_name, role_arn = _create_assumable_role()

    valid_policy = _valid_session_policy()
    assert len(valid_policy) <= 2048, len(valid_policy)
    control_resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("sim2real-behav-sess-ctrl-"),
        Policy=valid_policy,
    )
    assert "Credentials" in control_resp, control_resp

    session_name = ctx.unique_name("sim2real-behav-sess-")
    oversized = _oversized_session_policy()
    assert len(oversized) > 2048, len(oversized)

    code, message = _stable_error_code(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            Policy=oversized,
        ),
        transient=("AccessDenied", "InvalidClientTokenId"),
    )
    assert code == "ValidationError", code
    assert message == (
        f"1 validation error detected: Value '{oversized}' at 'policy' failed to satisfy "
        "constraint: Member must have length less than or equal to 2048"
    ), message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
