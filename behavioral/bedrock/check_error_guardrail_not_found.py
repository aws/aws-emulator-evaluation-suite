"""error-guardrail-not-found."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "error-guardrail-not-found"
GROUP = 'errors'
SERVICES = ['bedrock']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetGuardrail with a fake ID returns ResourceNotFoundException, contrasted
    against a real, freshly created guardrail recognized by the same operation."""
    bc = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-bedrock-gr-")
    created = bc.create_guardrail(
        name=name,
        blockedInputMessaging="Input blocked by guardrail.",
        blockedOutputsMessaging="Output blocked by guardrail.",
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": "sim2real-blocked-topic",
                    "definition": "Discussion of testing internals",
                    "type": "DENY",
                }
            ]
        },
        tags=[{"key": "sim2real", "value": "error-guardrail-not-found"}],
    )
    gid = created["guardrailId"]
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=gid))

    # positive control: the real, freshly created guardrail is recognized by GetGuardrail
    real = bc.get_guardrail(guardrailIdentifier=gid)
    assert real["guardrailId"] == gid, (
        f"Expected GetGuardrail to recognize the real guardrail {gid!r}, got {real.get('guardrailId')!r}"
    )

    # negative: a never-issued (but pattern-valid) guardrail id is not found
    got = _error(lambda: bc.get_guardrail(guardrailIdentifier="fake0000000000"))
    expected = ("ResourceNotFoundException", "This guardrail does not exist.")
    assert got == expected, f"Expected {expected!r} for fake guardrail, got {got!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
