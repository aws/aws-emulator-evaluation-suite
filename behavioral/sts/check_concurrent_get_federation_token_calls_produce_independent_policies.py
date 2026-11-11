"""concurrent-get-federation-token-calls-produce-independent-policies."""
from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-get-federation-token-calls-produce-independent-policies"
GROUP = "concurrency"
SERVICES = ["sts"]

_SUCCEEDED = ("<call succeeded>", None)
_S3_DENIED = (
    "User: {arn} is not authorized to perform: s3:ListAllMyBuckets "
    "because no session policy allows the s3:ListAllMyBuckets action"
)
_SM_DENIED = (
    "User: {arn} is not authorized to perform: secretsmanager:ListSecrets "
    "because no session policy allows the secretsmanager:ListSecrets action"
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent GetFederationToken calls with different single-action session policies yield
    isolated credentials: each session can call its own action and is denied, with the exact
    message, the sibling's action."""
    sts = ctx.client("sts")

    def _issue(action: str):
        name = f"fed-{uuid.uuid4().hex[:10]}"
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}],
        }
        resp = sts.get_federation_token(Name=name, Policy=json.dumps(policy))
        return resp["Credentials"], action, resp["FederatedUser"]["Arn"]

    plan = ["s3:ListAllMyBuckets"] * 3 + ["secretsmanager:ListSecrets"] * 3
    with ThreadPoolExecutor(max_workers=len(plan)) as pool:
        results = list(pool.map(_issue, plan))

    for creds, granted_action, fed_arn in results:
        s3_client = _client_with_creds(ctx, "s3", creds)
        sm_client = _client_with_creds(ctx, "secretsmanager", creds)
        s3_result = _error_retry(lambda: s3_client.list_buckets())
        sm_result = _error_retry(lambda: sm_client.list_secrets())
        if granted_action == "s3:ListAllMyBuckets":
            assert s3_result == _SUCCEEDED, (
                f"session policy granted {granted_action!r}: expected ListBuckets to succeed, "
                f"got {s3_result!r} -- a sibling call's grant must not leak in"
            )
            assert sm_result == ("AccessDeniedException", _SM_DENIED.format(arn=fed_arn)), (
                f"session policy granted only {granted_action!r}: expected ListSecrets to be "
                f"denied, got {sm_result!r} -- an unrelated action must not be usable"
            )
        else:
            assert sm_result == _SUCCEEDED, (
                f"session policy granted {granted_action!r}: expected ListSecrets to succeed, "
                f"got {sm_result!r} -- a sibling call's grant must not leak in"
            )
            assert s3_result == ("AccessDenied", _S3_DENIED.format(arn=fed_arn)), (
                f"session policy granted only {granted_action!r}: expected ListBuckets to be "
                f"denied with AccessDenied, got {s3_result!r} -- an unrelated action must "
                "not be usable"
            )


def _client_with_creds(ctx, service: str, creds: dict):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _error(fn):
    """The (code, message) of a failing call, or the _SUCCEEDED sentinel, which no
    (code, message) pair can equal."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _SUCCEEDED


def _error_retry(fn, timeout_s: float = 20.0, interval_s: float = 2.0):
    """Like _error, but retries InvalidClientTokenId, which a just-issued federation token
    returns until it propagates."""
    import time

    deadline = time.monotonic() + timeout_s
    last = _error(fn)
    while last[0] == "InvalidClientTokenId" and time.monotonic() < deadline:
        time.sleep(interval_s)
        last = _error(fn)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

