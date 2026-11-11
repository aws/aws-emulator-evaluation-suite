"""invocation-step-binary-payload-preserved."""
from __future__ import annotations

import base64
import datetime
import os

from behavioral_harness import tags

CHECK = "invocation-step-binary-payload-preserved"
GROUP = "server-side"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A base64-encoded binary blob written by PutInvocationStep as a text content block comes back
    byte-for-byte from GetInvocationStep: the service stores the string without re-encoding,
    truncating or otherwise mutating it."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session()["sessionId"]

    def _cleanup():
        # End the session if still ACTIVE (DeleteSession refuses an ACTIVE one), then delete it.
        from botocore.exceptions import ClientError

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

    ctx.on_cleanup(_cleanup)

    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]

    # Arbitrary binary blob (not valid UTF-8 on its own) -- base64-encode it
    # to a text-safe representation, exactly as a client would do to shuttle
    # binary data through a text field.
    raw_binary = os.urandom(256)
    encoded_text = base64.b64encode(raw_binary).decode("ascii")

    step_time = datetime.datetime.now(datetime.timezone.utc)
    put_resp = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepTime=step_time,
        payload={"contentBlocks": [{"text": encoded_text}]},
    )
    step_id = put_resp["invocationStepId"]

    fetched = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )
    content_blocks = fetched["invocationStep"]["payload"]["contentBlocks"]
    assert len(content_blocks) == 1, (
        f"expected exactly 1 content block, got {len(content_blocks)}: {content_blocks!r}"
    )
    returned_text = content_blocks[0]["text"]

    assert returned_text == encoded_text, (
        "base64-encoded binary payload was altered by the round-trip: "
        f"sent {len(encoded_text)} chars, got back {len(returned_text)} chars"
    )
    returned_binary = base64.b64decode(returned_text)
    assert returned_binary == raw_binary, (
        "decoded binary payload does not match the original bytes after "
        "the PutInvocationStep/GetInvocationStep round-trip"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
