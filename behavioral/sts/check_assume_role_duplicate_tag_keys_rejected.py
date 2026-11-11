"""assume-role-duplicate-tag-keys-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-duplicate-tag-keys-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRole with the same tag key twice is refused InvalidParameterValue, while one tag is
    accepted under a trust policy granting sts:TagSession."""

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

    iam = ctx.client("iam")

    trust = _trust_policy_for_account(actions=["sts:AssumeRole", "sts:TagSession"])
    _role_name, role_arn = _create_assumable_role(trust_policy=trust)

    ok = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
        Tags=[{"Key": "team", "Value": "a"}],
    )
    assert ok["Credentials"]["AccessKeyId"]

    code, message = _stable_refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            Tags=[
                {"Key": "team", "Value": "a"},
                {"Key": "team", "Value": "b"},
            ],
        ),
        transient=("AccessDenied", "InvalidClientTokenId"),
    )
    assert code == "InvalidParameterValue", code
    assert message == (
        "Duplicate tag keys found. Please note that Tag keys are case insensitive."
    ), message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
