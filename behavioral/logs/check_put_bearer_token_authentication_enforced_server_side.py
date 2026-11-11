"""put-bearer-token-authentication-enforced-server-side."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-bearer-token-authentication-enforced-server-side"
GROUP = "server-side"
SERVICES = ["logs"]

_AUTH_FAILED = "Authentication failed: Please make sure your API Key is valid."


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The OTLP endpoint refuses a valid bearer token with 403 and the auth-failed status until
    PutBearerTokenAuthentication enables auth, then accepts it while a wrong token gets 403; once auth
    is disabled the valid token gets 400 and the unsupported-operation status naming the group.
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    group_name = ctx.unique_name("sim2real-bearer-lg-")
    stream_name = "sim2real-bearer-stream"
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _delete_log_group(logs, group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    user_name = ctx.unique_name("sim2real-bearer-user-")
    try:
        iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    except ClientError as exc:
        raise AssertionError(f"cannot create prerequisite IAM user: {exc}") from exc
    ctx.on_cleanup(lambda: _delete_user(ctx, user_name))

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CallWithBearerToken", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
    }
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="sim2real-bearer-access",
        PolicyDocument=json.dumps(policy_document),
    )

    try:
        cred = iam.create_service_specific_credential(
            UserName=user_name, ServiceName="logs.amazonaws.com"
        )["ServiceSpecificCredential"]
    except ClientError as exc:
        raise AssertionError(f"cannot create prerequisite bearer-token credential: {exc}") from exc
    credential_id = cred["ServiceSpecificCredentialId"]
    # Bearer-token credentials return the secret as "ServiceCredentialSecret"; git-style
    # credentials use "ServicePassword".
    token = cred.get("ServicePassword") or cred.get("ServiceCredentialSecret")
    if not token:
        raise AssertionError(
            f"CreateServiceSpecificCredential response had no usable secret field: {sorted(cred)}"
        )
    ctx.on_cleanup(lambda: _delete_credential(iam, user_name, credential_id))

    bad_token = token[:-4] + ("0000" if not token.endswith("0000") else "1111")

    # Before auth is enabled, a bearer-token request is rejected. Polled so a transient
    # unreachable endpoint is retried and never counts as a rejection.
    status, pre_body = _poll_until_status(
        ctx, group_name, stream_name, token, expect_not=200, timeout_s=30
    )
    assert status != 200, (
        f"OTLP bearer request succeeded (status={status}) before PutBearerTokenAuthentication "
        "enabled auth for this log group"
    )
    assert status == 403, f"expected 403 before auth is enabled, got {status}"
    assert _rpc_reply(pre_body) == (7, _AUTH_FAILED), (
        f"unexpected rejection body before auth is enabled: {pre_body!r}"
    )

    # Polled for IAM/credential propagation delay.
    logs.put_bearer_token_authentication(
        logGroupIdentifier=group_name, bearerTokenAuthenticationEnabled=True
    )

    status, body = _poll_until_status(ctx, group_name, stream_name, token, 200, timeout_s=60)
    assert status == 200, (
        f"valid bearer token was never accepted after enabling auth (last status={status}, body={body!r})"
    )

    bad_status, bad_body = _poll_until_status(
        ctx, group_name, stream_name, bad_token, expect_not=200, timeout_s=30
    )
    assert bad_status == 403, f"expected 403 for an invalid bearer token, got {bad_status}"
    assert _rpc_reply(bad_body) == (7, _AUTH_FAILED), (
        f"unexpected rejection body for an invalid bearer token: {bad_body!r}"
    )

    # Once auth is disabled, the valid token is rejected too.
    logs.put_bearer_token_authentication(
        logGroupIdentifier=group_name, bearerTokenAuthenticationEnabled=False
    )
    disabled_status, disabled_body = _poll_until_status(
        ctx, group_name, stream_name, token, expect_not=200, timeout_s=30
    )
    assert disabled_status != 200, (
        f"valid bearer token was still accepted (status={disabled_status}) after disabling "
        "bearer token authentication"
    )
    assert disabled_status == 400, f"expected 400 once auth is disabled, got {disabled_status}"
    assert _rpc_reply(disabled_body) == (
        3,
        f"This operation is not supported for log group: {group_name}",
    ), f"unexpected rejection body once auth is disabled: {disabled_body!r}"


def _otlp_post(ctx: Any, log_group: str, log_stream: str, token: str) -> tuple[int | None, str]:
    # Derive the OTLP host from the client endpoint (https://logs.<region>.amazonaws.com on AWS).
    url = f"{ctx.client('logs').meta.endpoint_url.rstrip('/')}/v1/logs"
    now_ns = str(int(time.time() * 1_000_000_000))
    payload = {
        "resourceLogs": [
            {
                "resource": {"attributes": []},
                "scopeLogs": [
                    {
                        "scope": {"name": "sim2real", "version": "1.0.0"},
                        "logRecords": [
                            {
                                "timeUnixNano": now_ns,
                                "severityNumber": 9,
                                "severityText": "INFO",
                                "body": {"stringValue": "sim2real-otlp-bearer-check"},
                            }
                        ],
                    }
                ],
            }
        ]
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "x-aws-log-group": log_group,
            "x-aws-log-stream": log_stream,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        # A connection failure is not a status: None lets the poll retry it, and it can never
        # satisfy expect_not=200.
        return None, f"unreachable: {exc}"


def _poll_until_status(
    ctx: Any,
    log_group: str,
    log_stream: str,
    token: str,
    expect: int | None = None,
    expect_not: int | None = None,
    timeout_s: float = 60.0,
    interval_s: float = 5.0,
) -> tuple[int, str]:
    deadline = time.monotonic() + timeout_s
    status: int | None = None
    body = ""
    while time.monotonic() < deadline:
        status, body = _otlp_post(ctx, log_group, log_stream, token)
        if status is None:
            # Unreachable: retry; a connection failure must not satisfy expect_not.
            time.sleep(interval_s)
            continue
        if expect is not None and status == expect:
            return status, body
        if expect_not is not None and status != expect_not:
            return status, body
        time.sleep(interval_s)
    assert status is not None, (
        f"the OTLP endpoint was unreachable for the entire {timeout_s}s window ({body}); "
        "an unreachable target cannot demonstrate bearer-token enforcement"
    )
    return status, body


def _rpc_reply(body: str) -> tuple[int | None, str | None]:
    """Decode the protobuf google.rpc.Status the OTLP endpoint returns on a rejection:
    field 1 is the varint code, field 2 the length-delimited message."""
    raw = body.encode("latin-1", "replace")
    code: int | None = None
    message: str | None = None
    i = 0

    def _varint(j: int) -> tuple[int, int]:
        value, shift = 0, 0
        while True:
            b = raw[j]
            value |= (b & 0x7F) << shift
            j += 1
            if not b & 0x80:
                return value, j
            shift += 7

    try:
        while i < len(raw):
            key, i = _varint(i)
            field, wire_type = key >> 3, key & 7
            if wire_type == 0:
                value, i = _varint(i)
                if field == 1:
                    code = value
            elif wire_type == 2:
                length, i = _varint(i)
                chunk = raw[i : i + length]
                i += length
                if field == 2:
                    message = chunk.decode("utf-8", "replace")
            else:
                break
    except IndexError:
        pass
    return code, message


def _delete_log_group(logs_client: Any, group_name: str) -> None:
    try:
        logs_client.delete_log_group(logGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_credential(iam_client: Any, user_name: str, credential_id: str) -> None:
    try:
        iam_client.delete_service_specific_credential(
            UserName=user_name, ServiceSpecificCredentialId=credential_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_user(ctx: Any, user_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_user_policy(UserName=user_name, PolicyName="sim2real-bearer-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
