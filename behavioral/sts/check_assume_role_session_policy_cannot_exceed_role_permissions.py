"""assume-role-session-policy-cannot-exceed-role-permissions."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "assume-role-session-policy-cannot-exceed-role-permissions"
GROUP = 'overly-permissive'
SERVICES = ['sts']
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An allow-all session policy cannot broaden a role that only grants sts:GetCallerIdentity:
    that call still succeeds but s3:ListAllMyBuckets is AccessDenied, because effective
    permissions are the intersection of the role policy and the session policy."""

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
                return response.get("Error", {}).get("Code")
            return type(exc).__name__
        return _OK

    def _stable_error_code(fn, transient=(), attempts=8, interval_s=3.0):
        last = None
        for _ in range(attempts):
            last = _error_code(fn)
            if last not in transient:
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

    def _wait_creds_active(creds, service="sts"):
        # Freshly-issued temp creds are eventually consistent; poll on every target.
        probe = _client_with_credentials(service, creds)
        _poll_until(
            lambda: _error_code(lambda: probe.get_caller_identity()) == _OK,
            lambda ok: ok is True, timeout_s=60, interval_s=2.0,
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

    def _allow_all_policy():
        return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}

    iam = _make_client_for("iam")

    narrow = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"}],
    }
    _role_name, role_arn = _create_assumable_role(inline_policy=narrow)

    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
        Policy=json.dumps(_allow_all_policy()),
    )
    creds = resp["Credentials"]
    _wait_creds_active(creds)

    scoped_s3 = _client_with_credentials("s3", creds)
    scoped_sts = _client_with_credentials("sts", creds)

    # Positive control: rules out a target that denies every call from assumed credentials.
    positive_code = _stable_error_code(
        lambda: scoped_sts.get_caller_identity(),
        transient=("InvalidClientTokenId", "InvalidAccessKeyId"),
    )
    assert positive_code == _OK, (
        "role's own identity policy grants sts:GetCallerIdentity, expected success, "
        f"got code={positive_code!r}"
    )

    code = _stable_error_code(
        lambda: scoped_s3.list_buckets(),
        transient=("InvalidClientTokenId", "InvalidAccessKeyId"),
    )
    assert code == "AccessDenied", (
        "session policy must not grant permissions beyond the role's identity-based "
        f"policy, got code={code!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
