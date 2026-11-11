"""concurrent-create-invocation-same-id-single-winner."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-invocation-same-id-single-winner"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of 8 concurrent CreateInvocation calls with one invocationId, exactly one succeeds, the other 7 get
    ConflictException "Invocation with ID <id> already exists", and ListInvocations shows one."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session(tags={"sim2real": CHECK})
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    invocation_id = str(uuid.uuid4())
    racer_count = 8

    def _racer(_i: int):
        from botocore.exceptions import ClientError

        try:
            client.create_invocation(sessionIdentifier=session_id, invocationId=invocation_id)
            return ("ok", None, None)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"], err.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    )
    codes = {code for _, code, _ in failures}
    assert codes == {"ConflictException"}, f"expected only ConflictException, got {codes}"
    messages = {message for _, _, message in failures}
    expected_message = f"Invocation with ID {invocation_id} already exists"
    assert messages == {expected_message}, f"expected only {expected_message!r}, got {messages}"

    matching = [
        s
        for s in client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
        if s["invocationId"] == invocation_id
    ]
    assert len(matching) == 1, (
        f"expected exactly one invocation for {invocation_id}, found {len(matching)}"
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
