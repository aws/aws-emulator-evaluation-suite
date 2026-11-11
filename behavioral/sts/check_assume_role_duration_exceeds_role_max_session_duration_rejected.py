"""assume-role-duration-exceeds-role-max-session-duration-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-duration-exceeds-role-max-session-duration-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DurationSeconds within the API shape range but above the role's configured MaxSessionDuration is rejected.

    Distinct from the absolute 43200s API ceiling: here 7200s is a valid shape value,
    but the role caps sessions at 3600s, so STS must reject with ValidationError."""

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
        """(code, message, HTTP status) of the error ``fn`` raises; AssertionError when it succeeds."""
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return (error.get("Code"), error.get("Message"),
                    exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
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

    iam = ctx.client("iam")

    _role_name, role_arn = _create_assumable_role(max_session_duration=3600)
    session_name = ctx.unique_name("sim2real-behav-sess-")

    code, message, status = _stable_refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=7200
        ),
        transient=("AccessDenied", "InvalidClientTokenId"),
    )
    assert code == "ValidationError", (
        f"expected ValidationError for DurationSeconds=7200 against a role capped at "
        f"MaxSessionDuration=3600, got {code}"
    )
    assert status == 400, f"expected HTTP 400 for the refusal, got {status!r}"
    expected_message = "The requested DurationSeconds exceeds the MaxSessionDuration set for this role."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Restore leg: the identical DurationSeconds=7200 call must succeed once the role's
    # OWN MaxSessionDuration is raised to admit it -- proving the rejection above tracks
    # this role's configured ceiling rather than a hardcoded >3600 cutoff.
    raised_role_name, raised_role_arn = _create_assumable_role(max_session_duration=7200)
    raised_session_name = ctx.unique_name("sim2real-behav-sess-")
    before = datetime.now(timezone.utc)
    resp = sts.assume_role(
        RoleArn=raised_role_arn, RoleSessionName=raised_session_name, DurationSeconds=7200
    )
    creds = resp["Credentials"]
    assert creds.get("AccessKeyId"), (
        f"expected usable credentials once the role's own MaxSessionDuration admits 7200s, got {resp!r}"
    )
    elapsed = (creds["Expiration"] - before).total_seconds()
    assert 7150 <= elapsed <= 7260, (
        f"expected the granted session to expire ~7200s out once the role's own ceiling "
        f"admits it, got {elapsed}s"
    )
    # The twin's credentials really work: GetCallerIdentity with them names the twin session.
    expected_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{raised_role_name}/{raised_session_name}"
    identity = _client_with_credentials("sts", creds).get_caller_identity()
    assert identity["Arn"] == expected_arn, (
        f"the twin session's GetCallerIdentity must report {expected_arn!r}, got {identity['Arn']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
