"""structured-json-endpoint-partial-success-reports-refused-record-count."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "structured-json-endpoint-partial-success-reports-refused-record-count"
GROUP = "http-ingestion"
SERVICES = ["iam", "logs"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The Structured JSON endpoint returns an empty 200 body when every event in the request
    is accepted, and a partialSuccess body naming the rejected count and an error message when
    one event in the batch falls outside the ingestion time window.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_HTTP_Endpoints_StructuredJSON.html
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    group_name = ctx.unique_name("sim2real-structjson-lg-")
    stream_name = "sim2real-structjson-stream"
    logs.create_log_group(logGroupName=group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=group_name), "ResourceNotFoundException"))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    user_name = ctx.unique_name("sim2real-structjson-user-")
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
        PolicyName="sim2real-structjson-access",
        PolicyDocument=json.dumps(policy_document),
    )
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_user_policy(UserName=user_name, PolicyName="sim2real-structjson-access"),
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

    all_valid_payload = [
        {"timestamp": int(time.time() * 1000), "message": "sim2real-structjson-valid-one"},
        {"timestamp": int(time.time() * 1000), "message": "sim2real-structjson-valid-two"},
    ]

    # Polled for IAM/credential propagation: the bearer token is not usable the instant it is
    # created and enabled.
    status1, body1 = _poll_until_status(
        ctx, group_name, stream_name, token, all_valid_payload, expect=200, timeout_s=90
    )
    assert status1 == 200, (
        f"a request whose events are all valid should return 200 "
        f"(last status={status1}, body={body1!r})"
    )
    assert json.loads(body1) == {}, (
        f"expected an empty JSON object body when every event is accepted, got {body1!r}"
    )

    too_new_ts = int((time.time() + 3 * 3600) * 1000)
    mixed_payload = [
        {"timestamp": int(time.time() * 1000), "message": "sim2real-structjson-accepted"},
        {"timestamp": too_new_ts, "message": "sim2real-structjson-too-new-rejected"},
    ]
    status2, body2 = _structured_json_post(ctx, group_name, stream_name, token, mixed_payload)
    assert status2 == 200, (
        f"a partially-rejected batch still returns 200, got {status2} (body={body2!r})"
    )
    decoded2 = json.loads(body2)
    assert set(decoded2) == {"partialSuccess"}, f"expected only a partialSuccess object, got {decoded2!r}"
    partial = decoded2["partialSuccess"]
    assert set(partial) == {"rejectedLogRecords", "errorMessage"}, (
        f"expected partialSuccess to carry rejectedLogRecords and errorMessage, got {partial!r}"
    )
    assert partial["rejectedLogRecords"] == 1, (
        f"expected exactly 1 rejected record for the one too-far-in-the-future event, "
        f"got {partial['rejectedLogRecords']!r} (full response: {decoded2!r})"
    )
    # errorMessage is a JSON-encoded count per rejection reason; zero counts carry no reason.
    reasons = {k: v for k, v in json.loads(partial["errorMessage"]).items() if v}
    assert reasons == {"tooNewLogEventCount": 1}, (
        f"expected errorMessage to count the one too-new event, got {partial['errorMessage']!r}"
    )

    accepted_entry = mixed_payload[0]
    expected_messages = {
        json.dumps(entry, separators=(",", ":")) for entry in (*all_valid_payload, accepted_entry)
    }
    messages = _poll_for_messages(logs, group_name, stream_name, len(expected_messages), timeout_s=90)
    assert set(messages) == expected_messages, (
        f"GetLogEvents returned {messages!r}, expected exactly the three accepted event objects "
        f"{sorted(expected_messages)!r} and not the too-new rejected one"
    )


def _structured_json_post(
    ctx: Any, log_group: str, log_stream: str, token: str, payload: list
) -> tuple[int | None, str]:
    url = (
        f"{ctx.client('logs').meta.endpoint_url.rstrip('/')}/ingest/json"
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
    payload: list,
    expect: int,
    timeout_s: float = 60.0,
    interval_s: float = 5.0,
) -> tuple[int, str]:
    deadline = time.monotonic() + timeout_s
    status: int | None = None
    body = ""
    while time.monotonic() < deadline:
        status, body = _structured_json_post(ctx, log_group, log_stream, token, payload)
        if status == expect:
            return status, body
        time.sleep(interval_s)
    assert status is not None, (
        f"the Structured JSON endpoint was unreachable for the entire {timeout_s}s window ({body})"
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
