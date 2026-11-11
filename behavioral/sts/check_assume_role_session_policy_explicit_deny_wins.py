"""assume-role-session-policy-explicit-deny-wins."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "assume-role-session-policy-explicit-deny-wins"
GROUP = 'overly-permissive'
SERVICES = ['sts']
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An explicit Deny in the session policy overrides the role's Allow.

    The role has an allow-all identity policy and the session policy also allows
    everything but explicitly denies s3:ListAllMyBuckets. Explicit deny must win."""

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

    def _create_assumable_role(trust_policy=None, max_session_duration=3600, inline_policy=None):
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
        _wait_role_assumable(role_arn)
        return role_name, role_arn

    def _allow_all_policy():
        return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}

    iam = _make_client_for("iam")

    _role_name, role_arn = _create_assumable_role(inline_policy=_allow_all_policy())
    allow_all_session_policy = json.dumps(_allow_all_policy())
    deny_session_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
        ],
    })

    # --- Positive control: an allow-all session policy with no Deny must let the action
    # through. Without this, AccessDenied below would be indistinguishable from every scoped
    # session being denied regardless of the Deny statement.
    control = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("sim2real-behav-sess-ctrl-"),
        Policy=allow_all_session_policy,
    )
    _wait_creds_active(control["Credentials"])
    control_s3 = _client_with_credentials("s3", control["Credentials"])
    control_code = _stable_error_code(
        lambda: control_s3.list_buckets(),
        transient=("InvalidClientTokenId", "InvalidAccessKeyId"),
    )
    assert control_code == _OK, (
        f"s3:ListAllMyBuckets must succeed under an allow-all session policy with no Deny, "
        f"got code={control_code!r}"
    )

    # --- Break exactly one thing: the same allow-all statement, plus an explicit Deny for the
    # one action.
    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
        Policy=deny_session_policy,
    )
    _wait_creds_active(resp["Credentials"])
    scoped_s3 = _client_with_credentials("s3", resp["Credentials"])
    scoped_iam = _client_with_credentials("iam", resp["Credentials"])

    code = _stable_error_code(
        lambda: scoped_s3.list_buckets(),
        transient=("InvalidClientTokenId", "InvalidAccessKeyId"),
    )
    assert code == "AccessDenied", (
        f"explicit Deny in the session policy must override the role's Allow, got code={code!r}"
    )

    # --- Same session, independent action: the Deny is scoped to the one action, not a blanket
    # denial -- iam:ListRoles is allowed by the same two policies and must still succeed.
    sibling_code = _stable_error_code(
        lambda: scoped_iam.list_roles(),
        transient=("InvalidClientTokenId", "InvalidAccessKeyId"),
    )
    assert sibling_code == _OK, (
        f"iam:ListRoles is allowed by both the role's identity policy and the session policy, and "
        f"must still succeed while only s3:ListAllMyBuckets is denied, got code={sibling_code!r}"
    )

    # --- Restore: a fresh session on the same role, with the Deny statement removed, must let
    # the identical call succeed again -- proving the earlier denial was the Deny statement's
    # doing, not some other block on this role or account.
    restored = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("sim2real-behav-sess-restored-"),
        Policy=allow_all_session_policy,
    )
    _wait_creds_active(restored["Credentials"])
    restored_s3 = _client_with_credentials("s3", restored["Credentials"])
    restored_code = _stable_error_code(
        lambda: restored_s3.list_buckets(),
        transient=("InvalidClientTokenId", "InvalidAccessKeyId"),
    )
    assert restored_code == _OK, (
        f"removing the Deny statement must restore s3:ListAllMyBuckets on an identical call, "
        f"got code={restored_code!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
