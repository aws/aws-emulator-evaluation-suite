"""get-federation-token-no-policy-grants-no-permissions."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-no-policy-grants-no-permissions"
GROUP = 'overly-permissive'
SERVICES = ['sts']

_MANAGED_TAG_KEY = "sim2real:managed"


#: What ``_error`` returns for a call that succeeds: a code no AWS error can carry.
_SUCCEEDED = ("<call succeeded>", None)


def _error(fn):
    """fn()'s error (code, message), or ``_SUCCEEDED`` when the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return _SUCCEEDED


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
    """A client for *service* on the target, signed with the given (possibly temporary) credentials."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        },
    )


def _wait_for_creds(ctx, creds: dict) -> dict:
    """Block until new credentials authenticate; they are eventually consistent and can fail
    with InvalidClientTokenId / SignatureDoesNotMatch until they propagate."""
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


def _stable_error(fn, *, transient=("InvalidClientTokenId",), timeout_s: float = 150):
    """``_error(fn)`` retried past credential-propagation transients; new session tokens can
    flap between accepted and InvalidClientTokenId for about a minute. May return _SUCCEEDED."""
    transient_set = set(transient)
    return _poll_until(
        lambda: _error(fn),
        lambda err: err[0] not in transient_set,
        timeout_s=timeout_s,
        interval_s=4,
        description="error code stabilises past credential propagation",
    )


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


def _allow_all_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A federation token minted without Policy/PolicyArns has no permissions even for an
    allow-all caller: ListBuckets fails AccessDenied with the exact no-session-policy message,
    while a token whose Policy allows s3:ListAllMyBuckets can list (positive control).
    """
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    _user_name, _user_arn, user_creds = _create_user(
        ctx, iam, permissions_policy=_allow_all_policy()
    )
    client = _client_for(ctx, "sts", user_creds)

    positive_fed_name = "fed-" + uuid.uuid4().hex[:10]
    positive_resp = client.get_federation_token(
        Name=positive_fed_name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
            }
        ),
    )
    positive_creds = positive_resp["Credentials"]
    _wait_for_creds(ctx, positive_creds)
    positive_s3 = _client_for(ctx, "s3", positive_creds)
    positive = _stable_error(
        lambda: positive_s3.list_buckets(),
        transient=("InvalidClientTokenId", "InvalidAccessKeyId"),
    )
    assert positive == _SUCCEEDED, (
        "positive control failed: a federation token whose Policy explicitly allows "
        f"s3:ListAllMyBuckets must be able to make that call; got {positive!r}"
    )

    fed_name = "fed-" + uuid.uuid4().hex[:10]
    resp = client.get_federation_token(Name=fed_name)
    creds = resp["Credentials"]
    _wait_for_creds(ctx, creds)

    scoped_s3 = _client_for(ctx, "s3", creds)
    code, message = _stable_error(
        lambda: scoped_s3.list_buckets(),
        transient=("InvalidClientTokenId", "InvalidAccessKeyId"),
    )
    assert code == "AccessDenied", (
        "a federated session with no session policy must have no "
        f"permissions at all, got code={code!r}"
    )
    assert message == (
        f"User: arn:aws:sts::{account}:federated-user/{fed_name} is not authorized to perform: "
        "s3:ListAllMyBuckets because no session policy allows the s3:ListAllMyBuckets action"
    ), message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
