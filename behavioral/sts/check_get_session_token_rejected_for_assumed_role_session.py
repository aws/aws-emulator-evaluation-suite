"""get-session-token-rejected-for-assumed-role-session."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-token-rejected-for-assumed-role-session"
GROUP = 'overly-permissive'
SERVICES = ['sts']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSessionToken is refused with AccessDenied and its exact message for assumed-role
    credentials, even when the role's allow-all policy would permit it."""

    sts = ctx.client("sts")

    def _client_with_credentials(service, creds):
        return ctx.client(service, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    def _refusal(fn):
        """The (code, message) of a refused call. Raises when the call SUCCEEDS, so an
        over-permissive target is reported as such rather than as a code mismatch."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")

    def _succeeds(fn):
        try:
            fn()
        except ClientError:
            return False
        return True

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
        # Freshly-issued temporary credentials are eventually consistent.
        probe = _client_with_credentials(service, creds)
        _poll_until(
            lambda: _succeeds(probe.get_caller_identity),
            lambda ok: ok is True, timeout_s=60, interval_s=2.0,
            description="temporary credentials became active",
        )

    def _account_id():
        return sts.get_caller_identity()["Account"]

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _default_trust_policy():
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

    def _allow_all_policy():
        return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}

    iam = ctx.client("iam")

    # Positive control: rules out a blanket denial of GetSessionToken for every caller.
    positive = sts.get_session_token()
    assert positive["Credentials"].get("SessionToken"), (
        f"positive control failed: base caller could not GetSessionToken, got {positive!r}"
    )

    _role_name, role_arn = _create_assumable_role(inline_policy=_allow_all_policy())
    resp = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-")
    )
    _wait_creds_active(resp["Credentials"])
    client = _client_with_credentials("sts", resp["Credentials"])

    code, message = _poll_until(
        lambda: _refusal(client.get_session_token),
        lambda r: r[0] != "InvalidClientTokenId",
        timeout_s=30, interval_s=3.0, description="refusal past credential propagation",
    )
    assert code == "AccessDenied", (
        f"expected AccessDenied for an assumed-role session calling GetSessionToken, got {code!r}"
    )
    expected_message = "Cannot call GetSessionToken with session credentials"
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
