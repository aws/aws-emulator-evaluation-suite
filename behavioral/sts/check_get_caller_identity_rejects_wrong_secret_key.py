"""get-caller-identity-rejects-wrong-secret-key."""
from __future__ import annotations

import base64
import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-caller-identity-rejects-wrong-secret-key"
GROUP = 'overly-permissive'
SERVICES = ['sts']

_MANAGED_TAG_KEY = "sim2real:managed"

_SIGNATURE_MISMATCH_MESSAGE = (
    "The request signature we calculated does not match the signature you provided. Check "
    "your AWS Secret Access Key and signing method. Consult the service documentation for "
    "details."
)


def _error(fn):
    """The (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects this signature with SignatureDoesNotMatch, but it SUCCEEDED "
        f"and returned {result!r}"
    )


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


def _client_for(ctx, service: str, creds: dict, config: Config | None = None):
    """A client for *service* on the target, signed with the given (possibly temporary) credentials.

    ``ctx.client`` caches on the access key id, not the secret, so a client that reuses a real
    key id with a different secret passes its own ``config`` to get a separate client.
    """
    return ctx.client(
        service,
        config=config,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        },
    )


def _wait_for_creds(ctx, creds: dict) -> dict:
    """Block until a new access key authenticates; it is eventually consistent and can fail
    with InvalidClientTokenId / SignatureDoesNotMatch until it propagates."""
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
    """Create an IAM user + access key, confirmed usable. Returns (user_name, user_arn, creds)."""
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


def _bogus_long_term_creds() -> dict:
    """Well-formed but entirely fictitious long-term credentials."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    body = "".join(alphabet[b % len(alphabet)] for b in uuid.uuid4().bytes[:16])
    return {
        "AccessKeyId": "AKIA" + body,
        "SecretAccessKey": base64.b64encode(
            uuid.uuid4().bytes + uuid.uuid4().bytes
        ).decode()[:40],
    }

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A real access key id paired with a wrong secret fails SignatureDoesNotMatch with the exact
    message, so the refusal comes from SigV4 signature verification, not an unknown key.
    """
    iam = ctx.client("iam")
    _user_name, _user_arn, user_creds = _create_user(ctx, iam)
    tampered = {
        "AccessKeyId": user_creds["AccessKeyId"],
        "SecretAccessKey": _bogus_long_term_creds()["SecretAccessKey"],
    }

    tampered_sts = _client_for(
        ctx, "sts", tampered, config=Config(user_agent_extra="sim2real-tampered-secret")
    )
    code, message = _error(tampered_sts.get_caller_identity)
    assert code == "SignatureDoesNotMatch", (
        f"expected SignatureDoesNotMatch for a real access key id paired with a wrong "
        f"secret, got {code!r}"
    )
    assert message == _SIGNATURE_MISMATCH_MESSAGE, message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
