"""get-session-token-default-duration-is-twelve-hours."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-session-token-default-duration-is-twelve-hours"
GROUP = 'get-session-token'
SERVICES = ['sts']

# The tag the suite stamps on every resource it creates, so a leftover can be found by
# leftovers.
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observed: {last!r}"
            )
        time.sleep(interval_s)


def _client_for(ctx, service: str, creds: dict):
    """A client for *service* on the target, signed with the given (possibly temporary)
    credentials."""
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds.get("SessionToken"),
    })


def _wait_for_creds(ctx, creds: dict) -> dict:
    """Block until freshly-minted credentials are usable.

    A brand new access key is not immediately valid everywhere; the first signed call can
    fail with InvalidClientTokenId / SignatureDoesNotMatch until it propagates. Poll
    GetCallerIdentity (which every principal may call) until it succeeds so checks never
    flake on propagation.
    """
    probe_client = _client_for(ctx, "sts", creds)

    def probe():
        try:
            probe_client.get_caller_identity()
            return True
        except Exception:  # noqa: BLE001
            return False

    _poll_until(
        probe,
        lambda ok: ok,
        timeout_s=60,
        interval_s=2,
        description="new access key becomes usable",
    )
    return creds


def _delete_user(iam, name: str) -> None:
    """Full IAM user teardown: keys and inline policies must go before the user itself."""
    for key in iam.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
        try:
            iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    for policy in iam.list_user_policies(UserName=name).get("PolicyNames", []):
        try:
            iam.delete_user_policy(UserName=name, PolicyName=policy)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    iam.delete_user(UserName=name)


def _create_user(ctx, iam, permissions_policy: dict | None = None):
    """Create an IAM user + access key. Returns (user_name, user_arn, creds).

    The returned credentials are already confirmed usable (see ``_wait_for_creds``) so
    callers never race key propagation.
    """
    name = ctx.unique_name("sim2real-behav-sts-user-")
    resp = iam.create_user(UserName=name, Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}])
    ctx.on_cleanup(lambda: _delete_user(iam, name))
    arn = resp["User"]["Arn"]
    if permissions_policy is not None:
        iam.put_user_policy(
            UserName=name, PolicyName="perm", PolicyDocument=json.dumps(permissions_policy)
        )
    key = iam.create_access_key(UserName=name)["AccessKey"]
    creds = {
        "AccessKeyId": key["AccessKeyId"],
        "SecretAccessKey": key["SecretAccessKey"],
    }
    _wait_for_creds(ctx, creds)
    return name, arn, creds

@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSessionToken without DurationSeconds defaults to a 43200s (12 hour) session for an IAM user."""
    iam = ctx.client("iam")
    _user_name, _user_arn, user_creds = _create_user(ctx, iam)
    client = _client_for(ctx, "sts", user_creds)

    before = datetime.now(timezone.utc)
    resp = client.get_session_token()
    expiration = resp["Credentials"]["Expiration"]

    delta = (expiration - before).total_seconds()
    assert 42000 <= delta <= 44400, f"expected ~43200s default duration, got {delta}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
