"""get-session-token-cannot-call-other-sts-operations."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-token-cannot-call-other-sts-operations"
GROUP = 'overly-permissive'
SERVICES = ['sts']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSessionToken creds may NOT call other STS APIs even with an allow-all user policy.

    Real STS refuses to serve any STS API other than AssumeRole/GetCallerIdentity
    to a GetSessionToken-derived session, regardless of IAM policy."""

    user_creds, _ = _iam_user_creds(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:*", "Resource": "*"}],
        },
    )
    sts = ctx.client("sts", creds=user_creds)

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

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _try_caller_identity(client):
        try:
            return client.get_caller_identity()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidClientTokenId":
                return None
            raise

    session_resp = sts.get_session_token()
    creds = session_resp["Credentials"]
    session_client = _client_with_credentials("sts", creds)

    # Positive control: the session-token creds must work for at least one STS API
    # (GetCallerIdentity), so the AccessDenied below is the GetFederationToken-specific
    # restriction and not evidence of creds that are broadly broken or denied. Freshly
    # issued temporary credentials are eventually consistent, so poll to the first success.
    identity = _poll_until(
        lambda: _try_caller_identity(session_client), lambda r: r is not None,
        timeout_s=60, interval_s=2.0, description="temporary credentials became active",
    )
    assert identity.get("Arn"), (
        "GetSessionToken credentials must be able to call GetCallerIdentity "
        f"(positive control), got response={identity!r}"
    )

    code, message = _poll_until(
        lambda: _refusal(
            lambda: session_client.get_federation_token(Name="sim2realbehavprobe")
        ),
        lambda r: r[0] != "InvalidClientTokenId",
        timeout_s=30, interval_s=3.0, description="refusal past credential propagation",
    )
    assert code == "AccessDenied", (
        "GetSessionToken credentials must not be able to call GetFederationToken "
        f"even with an allow-all identity policy, got code={code!r}"
    )
    expected_message = "Cannot call GetFederationToken with session credentials"
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )


def _iam_user_creds(ctx, policy=None):
    """A fresh IAM user's long-term access key (``creds`` for ctx.client) and the user's ARN.

    GetSessionToken and GetFederationToken take an IAM user's long-term credentials, so the
    check signs them with a user of its own instead of the runner's identity.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-stsuser-")
    user = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    if policy is not None:
        iam.put_user_policy(
            UserName=user_name, PolicyName="sim2real-behav-sts", PolicyDocument=json.dumps(policy)
        )
        ctx.on_cleanup(
            lambda: iam.delete_user_policy(UserName=user_name, PolicyName="sim2real-behav-sts")
        )
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id))
    creds = {"aws_access_key_id": key_id, "aws_secret_access_key": key["SecretAccessKey"]}
    # A new access key is eventually consistent: poll until STS accepts it.
    probe = ctx.client("sts", creds=creds)
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, max(left - 30.0, 0.0)))
    while True:
        try:
            probe.get_caller_identity()
            return creds, user["Arn"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the new IAM user's access key never authenticated: {code!r}"
                ) from exc
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
