"""guardrail-delete."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", _unique_name("gr-"))
    kwargs.setdefault("blockedInputMessaging", "Input blocked by guardrail.")
    kwargs.setdefault("blockedOutputsMessaging", "Output blocked by guardrail.")
    kwargs.setdefault("tags", [{"key": "sim2real-check", "value": CHECK}])
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: _delete_guardrail_if_present(bc, resp["guardrailId"]))
    return resp


def _delete_guardrail_if_present(bc, gid):
    try:
        bc.delete_guardrail(guardrailIdentifier=gid)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

CHECK = "guardrail-delete"
GROUP = 'guardrails'
SERVICES = ['bedrock']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteGuardrail, GetGuardrail eventually returns ResourceNotFoundException,
    and a mutation against the dead id also fails."""
    bc = ctx.client("bedrock")

    name = _unique_name("gr-")
    create_resp = _create_guardrail(bc, ctx,
        name=name,
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": "sim2real-delete-topic",
                    "definition": "Topic for delete test",
                    "type": "DENY",
                }
            ]
        })
    gid = create_resp["guardrailId"]

    # Positive control: the guardrail is real and reachable before we delete it —
    # otherwise a target that never actually created anything would still pass below.
    before = bc.get_guardrail(guardrailIdentifier=gid)
    assert before["guardrailId"] == gid, (
        f"Expected freshly created guardrail {gid!r} to be readable, got {before.get('guardrailId')!r}"
    )

    bc.delete_guardrail(guardrailIdentifier=gid)

    # Deletion may be eventually consistent — poll briefly, then demand the terminal state.
    code = message = None
    for _ in range(10):
        try:
            bc.get_guardrail(guardrailIdentifier=gid)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code, message = error.get("Code"), error.get("Message")
            if code == "ResourceNotFoundException":
                break
        time.sleep(1)
    assert code == "ResourceNotFoundException", (
        f"Expected ResourceNotFoundException after delete, got {code!r}"
    )
    expected_get = "This guardrail does not exist."
    assert message == expected_get, f"Expected GetGuardrail message {expected_get!r}, got {message!r}"

    # A mutation against the dead id must fail too, not silently succeed. The update request must
    # otherwise be well-formed, so it repeats the same policy the guardrail was created with.
    update_code, update_msg = _error(lambda: bc.update_guardrail(
        guardrailIdentifier=gid,
        name=name,
        blockedInputMessaging="Input blocked by guardrail.",
        blockedOutputsMessaging="Output blocked by guardrail.",
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": "sim2real-delete-topic",
                    "definition": "Topic for delete test",
                    "type": "DENY",
                }
            ]
        },
    ))
    assert update_code == "ResourceNotFoundException", (
        f"Expected UpdateGuardrail on a deleted guardrail to be ResourceNotFoundException, got {update_code!r}: {update_msg!r}"
    )
    expected_update = "This guardrail does not exist."
    assert update_msg == expected_update, (
        f"Expected UpdateGuardrail message {expected_update!r}, got {update_msg!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
