"""create-invocation-auto-generates-id."""
from __future__ import annotations

import re

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-invocation-auto-generates-id"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]

_UUID_RE = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInvocation without an explicit invocationId server-generates a well-formed UUID."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]

    def _cleanup():
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

    created = client.create_invocation(sessionIdentifier=session_id)
    invocation_id = created["invocationId"]
    assert _UUID_RE.match(invocation_id), f"invocationId {invocation_id!r} is not a UUID"

    listed = client.list_invocations(sessionIdentifier=session_id)
    ids = [s["invocationId"] for s in listed["invocationSummaries"]]
    assert invocation_id in ids, f"created invocationId {invocation_id!r} not in ListInvocations {ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
