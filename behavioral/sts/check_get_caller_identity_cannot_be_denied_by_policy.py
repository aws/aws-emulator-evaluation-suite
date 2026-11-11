"""get-caller-identity-cannot-be-denied-by-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-caller-identity-cannot-be-denied-by-policy"
GROUP = 'credential-issuance'
SERVICES = ['sts']


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCallerIdentity succeeds despite a session-policy explicit Deny, because it needs no
    permissions, while the same Deny blocks s3:ListAllMyBuckets with the exact AccessDenied."""

    sts = ctx.client("sts")

    def _client_with_credentials(service, creds):
        return ctx.client(service, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        })

    def _client_error(fn):
        """The (code, message) of the ClientError ``fn`` raises; raises AssertionError on success."""
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")

    def _stable_client_error(fn, transient=(), attempts=8, interval_s=3.0):
        last = None
        for _ in range(attempts):
            last = _client_error(fn)
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

    account = _account_id()
    role_name, role_arn = _create_assumable_role(inline_policy=_allow_all_policy())
    session_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "sts:GetCallerIdentity", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
        ],
    }
    session_name = ctx.unique_name("sim2real-behav-sess-")

    resp = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=session_name, Policy=json.dumps(session_policy)
    )
    client = _client_with_credentials("sts", resp["Credentials"])
    scoped_s3 = _client_with_credentials("s3", resp["Credentials"])

    # Control: proves the session policy is enforced at all.
    s3_error = _stable_client_error(
        lambda: scoped_s3.list_buckets(),
        transient=("InvalidClientTokenId", "InvalidAccessKeyId"),
    )
    assert s3_error == (
        "AccessDenied",
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{session_name} is not authorized "
        "to perform: s3:ListAllMyBuckets with an explicit deny in a session policy",
    ), f"control failed: session policy Deny should block s3:ListAllMyBuckets, got {s3_error!r}"

    identity = _retry_until_token_valid(lambda: client.get_caller_identity())
    assert identity["Arn"] == (
        f"arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}"
    ), identity

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
