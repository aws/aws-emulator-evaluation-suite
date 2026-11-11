"""create-assistant-client-token-idempotent-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-assistant-client-token-idempotent-conflict-rejected"
GROUP = "idempotency"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing the same clientToken with identical parameters returns the original assistant
    idempotently (no duplicate created); reusing it with a different name is rejected with
    ConflictException."""
    wisdom = ctx.client("wisdom")
    token = ctx.unique_name("sim2real-behav-token-")
    name = ctx.unique_name("sim2real-behav-asst-")

    resource_tags = {"team": "support", "stage": "sim2real-behav"}
    first = wisdom.create_assistant(clientToken=token, name=name, type="AGENT", tags=resource_tags)["assistant"]
    assistant_id = first["assistantId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))

    # positive control: same token + identical params (including tags, which the target
    # folds into idempotency-key equality) is idempotent, returns the same resource
    repeat = wisdom.create_assistant(clientToken=token, name=name, type="AGENT", tags=resource_tags)["assistant"]
    assert repeat["assistantId"] == assistant_id, (
        f"expected replayed clientToken to return the original assistantId {assistant_id!r}, "
        f"got {repeat['assistantId']!r}"
    )

    listed = _list_all_assistants(wisdom)
    matches = [a for a in listed if a["assistantId"] == assistant_id]
    assert len(matches) == 1, f"expected exactly 1 assistant {assistant_id!r} in list_assistants, found {len(matches)}"

    # break exactly one thing: reuse the token with a different name
    code, message = _error(
        lambda: wisdom.create_assistant(clientToken=token, name=ctx.unique_name("sim2real-behav-other-"), type="AGENT")
    )
    assert code == "ConflictException", f"expected ConflictException for reused clientToken with a different name, got {code!r}"
    assert message == "Idempotency conflict", f"expected the idempotency-conflict message, got {message!r}"

    # effect absent: no second assistant with the conflicting token/name was created
    listed_after = _list_all_assistants(wisdom)
    matches_after = [a for a in listed_after if a["assistantId"] == assistant_id]
    assert len(matches_after) == 1, (
        f"expected the rejected create to leave exactly 1 assistant {assistant_id!r} in list_assistants, "
        f"found {len(matches_after)}"
    )


def _list_all_assistants(wisdom):
    out = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = wisdom.list_assistants(**kwargs)
        out.extend(resp.get("assistantSummaries", []))
        token = resp.get("nextToken")
        if not token:
            break
    return out


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
