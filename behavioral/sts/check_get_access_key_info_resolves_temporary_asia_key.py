"""get-access-key-info-resolves-temporary-asia-key."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-access-key-info-resolves-temporary-asia-key"
GROUP = 'credential-issuance'
SERVICES = ['sts']


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccessKeyInfo resolves an AssumeRole-issued ASIA access key id to the caller's account,
    because the account is encoded in the key id itself, not only in persisted IAM keys."""

    sts = ctx.client("sts")

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
    _role_name, role_arn = _create_assumable_role()
    resp = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-")
    )
    temp_key_id = resp["Credentials"]["AccessKeyId"]
    assert temp_key_id.startswith("ASIA"), (
        f"expected an ASIA-prefixed temporary access key from AssumeRole, got prefix "
        f"{temp_key_id[:4]!r}"
    )

    info = sts.get_access_key_info(AccessKeyId=temp_key_id)
    assert info["Account"] == account, (
        f"expected GetAccessKeyInfo({temp_key_id}) to resolve to account {account}, got {info}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
