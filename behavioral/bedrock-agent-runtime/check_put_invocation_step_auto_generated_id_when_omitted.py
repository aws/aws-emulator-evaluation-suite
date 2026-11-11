"""put-invocation-step-auto-generated-id-when-omitted."""
from __future__ import annotations

import datetime
import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-invocation-step-auto-generated-id-when-omitted"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]

_UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """When invocationStepId is omitted from PutInvocationStep, the service generates a
    fresh UUID for it, returns that id, and the step is retrievable under that id with the
    payload intact."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    invocation_id = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_id, invocationId=invocation_id)

    payload = {"contentBlocks": [{"text": "auto-id step"}]}
    put_resp = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepTime=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        payload=payload,
    )
    generated_id = put_resp["invocationStepId"]
    assert _UUID_RE.match(generated_id), f"not a UUID: {generated_id}"

    got = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=generated_id,
    )["invocationStep"]

    assert got["payload"] == payload, f"payload mismatch: expected {payload}, got {got['payload']}"
    assert got["invocationId"] == invocation_id, (
        f"invocationId mismatch: expected {invocation_id}, got {got['invocationId']}"
    )


def _safe_delete_session(client, session_id: str) -> None:
    try:
        status = client.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
        try:
            client.end_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        client.delete_session(sessionIdentifier=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
