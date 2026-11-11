"""hlc-endpoint-event-shapes-accepted-missing-event-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hlc-endpoint-event-shapes-accepted-missing-event-rejected"
GROUP = "http-ingestion"
SERVICES = ["logs", "iam"]

_MISSING_EVENT_BODY = {"message": "All events were invalid"}


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The HLC endpoint accepts a bearer-token body carrying an "event" field, single object or
    array alike, but rejects one with no "event" field at all with 400; GetLogEvents reads back
    only the two accepted bodies.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_HLC_Endpoint.html
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    group_name = ctx.unique_name("sim2real-hlc-lg-")
    stream_name = "sim2real-hlc-stream"
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=group_name), "ResourceNotFoundException"))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    user_name = ctx.unique_name("sim2real-hlc-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: iam.delete_user(UserName=user_name), "NoSuchEntity"))

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
        PolicyName="sim2real-hlc-access",
        PolicyDocument=json.dumps(policy_document),
    )
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_user_policy(UserName=user_name, PolicyName="sim2real-hlc-access"),
            "NoSuchEntity",
        )
    )

    cred = iam.create_service_specific_credential(
        UserName=user_name, ServiceName="logs.amazonaws.com"
    )["ServiceSpecificCredential"]
    credential_id = cred["ServiceSpecificCredentialId"]
    token = cred.get("ServicePassword") or cred.get("ServiceCredentialSecret")
    assert token, f"CreateServiceSpecificCredential had no usable secret field: {sorted(cred)}"
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_service_specific_credential(
                UserName=user_name, ServiceSpecificCredentialId=credential_id
            ),
            "NoSuchEntity",
        )
    )

    logs.put_bearer_token_authentication(
        logGroupIdentifier=group_name, bearerTokenAuthenticationEnabled=True
    )

    single_payload = {"event": "sim2real-hlc-single-event"}
    array_payload = {
        "event": [
            {"event": "sim2real-hlc-array-event-one"},
            {"event": "sim2real-hlc-array-event-two"},
        ]
    }
    missing_payload = {"host": "sim2real-hlc-no-event-field"}

    # Polled for IAM/credential propagation: the bearer token is not usable the instant it is
    # created and enabled.
    status1, body1 = _poll_until_status(
        ctx, group_name, stream_name, token, single_payload, expect=200, timeout_s=90
    )
    assert status1 == 200, (
        f"a top-level object carrying an \"event\" field was never accepted "
        f"(last status={status1}, body={body1!r})"
    )
    assert json.loads(body1) == {}, f"unexpected success body for a single-object event: {body1!r}"

    status2, body2 = _hlc_post(ctx, group_name, stream_name, token, array_payload)
    assert status2 == 200, (
        f"a top-level object whose \"event\" field holds an array of sub-events was rejected "
        f"(status={status2}, body={body2!r})"
    )
    assert json.loads(body2) == {}, f"unexpected success body for an event-array object: {body2!r}"

    status3, body3 = _hlc_post(ctx, group_name, stream_name, token, missing_payload)
    assert status3 == 400, (
        f"a top-level object with no \"event\" field at all should be rejected with 400, "
        f"got {status3} (body={body3!r})"
    )
    assert json.loads(body3) == _MISSING_EVENT_BODY, (
        f"unexpected rejection body for a body with no \"event\" field: {body3!r}"
    )

    expected_messages = {
        json.dumps(single_payload, separators=(",", ":")),
        json.dumps(array_payload, separators=(",", ":")),
    }
    messages = _poll_for_messages(logs, group_name, stream_name, len(expected_messages), timeout_s=90)
    assert set(messages) == expected_messages, (
        f"GetLogEvents returned {messages!r}, expected exactly the two accepted bodies "
        f"{sorted(expected_messages)!r} and not the body missing \"event\""
    )


def _hlc_post(ctx: Any, log_group: str, log_stream: str, token: str, payload: dict) -> tuple[int | None, str]:
    url = (
        f"{ctx.client('logs').meta.endpoint_url.rstrip('/')}/services/collector/event"
        f"?logGroup={log_group}&logStream={log_stream}"
    )
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        # A connection failure is not a status: None lets the poll retry it.
        return None, f"unreachable: {exc}"


def _poll_until_status(
    ctx: Any,
    log_group: str,
    log_stream: str,
    token: str,
    payload: dict,
    expect: int,
    timeout_s: float = 60.0,
    interval_s: float = 5.0,
) -> tuple[int, str]:
    deadline = time.monotonic() + timeout_s
    status: int | None = None
    body = ""
    while time.monotonic() < deadline:
        status, body = _hlc_post(ctx, log_group, log_stream, token, payload)
        if status == expect:
            return status, body
        time.sleep(interval_s)
    assert status is not None, (
        f"the HLC endpoint was unreachable for the entire {timeout_s}s window ({body})"
    )
    return status, body


def _poll_for_messages(logs_client: Any, group_name: str, stream_name: str, want: int, timeout_s: float = 60.0) -> list[str]:
    deadline = time.monotonic() + timeout_s
    messages: list[str] = []
    while time.monotonic() < deadline:
        resp = logs_client.get_log_events(
            logGroupName=group_name, logStreamName=stream_name, startFromHead=True
        )
        messages = [e["message"] for e in resp["events"]]
        if len(messages) >= want:
            return messages
        time.sleep(3)
    return messages


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
