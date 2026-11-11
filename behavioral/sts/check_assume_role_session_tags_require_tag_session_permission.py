"""assume-role-session-tags-require-tag-session-permission."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "assume-role-session-tags-require-tag-session-permission"
GROUP = 'overly-permissive'
SERVICES = ['sts']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRole with session Tags is AccessDenied, with a message naming sts:TagSession, when the
    trust policy grants only sts:AssumeRole; the same AssumeRole without Tags succeeds."""

    sts = ctx.client("sts")

    def _make_client_for(service):
        return ctx.client(service)

    def _client_with_credentials(service, creds):
        return ctx.client(service, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    def _error_detail(fn):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            if response is not None:
                err = response.get("Error", {})
                return err.get("Code"), err.get("Message", "")
            return type(exc).__name__, str(exc)
        raise AssertionError(
            "session tagging must be denied without sts:TagSession, but the call "
            f"SUCCEEDED and returned {result!r}"
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

    def _trust_policy_for_account(actions=None, extra_condition=None):
        account_id = _account_id()
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": actions if actions is not None else "sts:AssumeRole",
        }
        if extra_condition is not None:
            stmt["Condition"] = extra_condition
        return {"Version": "2012-10-17", "Statement": [stmt]}

    iam = _make_client_for("iam")

    trust = _trust_policy_for_account(actions="sts:AssumeRole")
    # Positive control: _create_assumable_role polls untagged AssumeRole until it succeeds.
    role_name, role_arn = _create_assumable_role(trust_policy=trust)

    session_tags = [{"Key": "team", "Value": "a"}]

    def _tagged_assume():
        return sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            Tags=session_tags,
        )

    caller_arn = sts.get_caller_identity()["Arn"]
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: sts:TagSession on resource: {role_arn}"
    )
    # A replica still catching up to the new role denies the BASE AssumeRole action itself: a
    # propagation artifact, not the TagSession answer being polled for.
    propagation_message = (
        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}"
    )
    transient = {
        "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException",
        "EndpointConnectionError", "ConnectionError", "ConnectTimeoutError", "ReadTimeoutError",
    }

    def _is_terminal(v):
        code, message = v
        if code in transient:
            return False
        return not (code == "AccessDenied" and message == propagation_message)

    code, message = _poll_until(
        lambda: _error_detail(_tagged_assume), _is_terminal, timeout_s=60, interval_s=3.0,
        description="the AssumeRole+Tags denial reaches a stable terminal code",
    )
    assert code == "AccessDenied", (
        "session tagging must require sts:TagSession in the trust policy, "
        f"got code={code!r} message={message!r}"
    )
    assert message == expected_message, (
        "the denial must be ATTRIBUTED to sts:TagSession specifically -- otherwise 'rejects "
        f"tagged AssumeRole' is indistinguishable from 'rejects every AssumeRole'; "
        f"expected {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
