"""assume-role-concurrent-calls-produce-unique-credentials."""
from __future__ import annotations

import concurrent.futures
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "assume-role-concurrent-calls-produce-unique-credentials"
GROUP = 'credential-issuance'
SERVICES = ['sts']


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent AssumeRole calls against the same role each get distinct, non-colliding credentials."""

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

    iam = ctx.client("iam")

    _role_name, role_arn = _create_assumable_role()
    session_names = [ctx.unique_name(f"sim2real-behav-sess-{i}-") for i in range(8)]

    def make_call(session_name):
        # Trust-policy propagation is per-STS-node eventually consistent, so a racer
        # can still see AccessDenied right after warmup succeeded on another node.
        # Retry only that transient so a genuine authorization failure still surfaces.
        def call():
            last = None
            for _ in range(8):
                try:
                    return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
                except Exception as exc:  # noqa: BLE001
                    last = exc
                    response = getattr(exc, "response", None)
                    code = response.get("Error", {}).get("Code") if response else None
                    if code != "AccessDenied":
                        raise
                    time.sleep(0.5)
            raise last

        return call

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(session_names)) as ex:
        futures = [(sn, ex.submit(make_call(sn))) for sn in session_names]
        for sn, fut in futures:
            try:
                results.append((sn, fut.result(timeout=180)))
            except Exception as exc:  # noqa: BLE001
                results.append((sn, exc))

    successes = [(sn, r) for sn, r in results if not isinstance(r, BaseException)]
    failures = [type(r).__name__ for _, r in results if isinstance(r, BaseException)]
    assert len(successes) == len(session_names), failures

    access_key_ids = {r["Credentials"]["AccessKeyId"] for _, r in successes}
    session_tokens = {r["Credentials"]["SessionToken"] for _, r in successes}
    assert len(access_key_ids) == len(session_names), "AccessKeyId collision under concurrency"
    assert len(session_tokens) == len(session_names), "SessionToken collision under concurrency"

    # Independent read at the destination: use each issued credential set to call
    # GetCallerIdentity (a different operation than AssumeRole, through a client built
    # from nothing but the returned keys) and confirm it resolves to that session's own
    # assumed-role identity, not merely a distinct opaque token string.
    def _expected_assumed_role_arn(session_name):
        partition = role_arn.split(":")[1]
        account_id = role_arn.split(":")[4]
        role_name_part = role_arn.split("/")[-1]
        return f"arn:{partition}:sts::{account_id}:assumed-role/{role_name_part}/{session_name}"

    identities = {}
    for sn, r in successes:
        caller_client = _client_with_credentials("sts", r["Credentials"])
        identity = caller_client.get_caller_identity()
        expected_arn = _expected_assumed_role_arn(sn)
        assert identity["Arn"] == expected_arn, (
            f"GetCallerIdentity via session {sn!r}'s credentials returned "
            f"Arn={identity['Arn']!r}, expected {expected_arn!r}"
        )
        identities[sn] = identity["Arn"]

    assert len(set(identities.values())) == len(session_names), (
        f"GetCallerIdentity resolved colliding identities across concurrent sessions: {identities}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
