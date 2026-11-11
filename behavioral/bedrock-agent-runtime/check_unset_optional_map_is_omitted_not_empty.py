"""unset-optional-map-is-omitted-not-empty."""
# An optional map the caller never set must be ABSENT from the response, not present-and-empty.
#
# MEASURED against the live service: CreateSession with no metadata returns exactly
# {createdAt, sessionArn, sessionId, sessionStatus} -- sessionMetadata is not present at all.
#
# Returning `{}` where the service omits a member is an EXTRA key, so this asserts the exact key set.
#
# Severity, stated so nobody over-invests: botocore barely sees this ({} vs None, both falsy). It bites a
# provider doing describe -> diff -> apply, which can show a perpetual diff.
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unset-optional-map-is-omitted-not-empty"
GROUP = "representation"
SERVICES = ["bedrock-agent-runtime"]

OPTIONAL_MAP = "sessionMetadata"
# MEASURED: exactly these members come back for a session created with no arguments.
CREATE_MEMBERS = {"createdAt", "sessionArn", "sessionId", "sessionStatus"}
METADATA = {"probe": "set-on-purpose"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An optional map left unset is ABSENT from the response, not present-and-empty -- and the same
    member IS present, with the value given, when the caller does set it."""
    br = ctx.client("bedrock-agent-runtime")

    # --- Beat 1: created with NO metadata -- the member must be absent from Create's response -------
    created = br.create_session()
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _delete_session(br, session_id))
    body = {k: v for k, v in created.items() if k != "ResponseMetadata"}
    assert OPTIONAL_MAP not in body, (
        f"an unset optional map must be OMITTED, not returned empty; CreateSession returned "
        f"{OPTIONAL_MAP}={body.get(OPTIONAL_MAP)!r}. AWS omits the member when it was never set"
    )
    assert set(body) == CREATE_MEMBERS, (
        f"CreateSession's member set must be exactly {sorted(CREATE_MEMBERS)!r}; got "
        f"{sorted(body)!r}. Asserting the SET, not membership, is the whole point -- a membership test "
        f"cannot see a member that should not be there"
    )

    # --- Beat 2: and absent from the READ path too --------------------------------------------------
    # Asserted separately on the read path: a target could omit the member on create and synthesise
    # it on read.
    fetched = {
        k: v
        for k, v in br.get_session(sessionIdentifier=session_id).items()
        if k != "ResponseMetadata"
    }
    assert OPTIONAL_MAP not in fetched, (
        f"GetSession on a session created without metadata must omit {OPTIONAL_MAP!r}; got "
        f"{fetched.get(OPTIONAL_MAP)!r}"
    )

    # --- Beat 3: the control -- when metadata IS set, the member comes back with that value ---------
    # Without this, Beat 1 passes against a target that never returns the member under any
    # circumstances, which is a different defect wearing the same shape.
    with_meta = br.create_session(sessionMetadata=METADATA)
    with_meta_id = with_meta["sessionId"]
    ctx.on_cleanup(lambda: _delete_session(br, with_meta_id))
    read_back = br.get_session(sessionIdentifier=with_meta_id)
    assert read_back.get(OPTIONAL_MAP) == METADATA, (
        f"a session created WITH metadata must report it: expected {METADATA!r}, got "
        f"{read_back.get(OPTIONAL_MAP)!r}. If this fails, the member is simply never returned and "
        f"Beat 1 proved nothing"
    )


# ===== helpers =====


def _delete_session(br, session_id: str) -> None:
    """End the session if still ACTIVE (DeleteSession refuses an ACTIVE one), then delete it."""
    try:
        status = br.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
        try:
            br.end_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        br.delete_session(sessionIdentifier=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
