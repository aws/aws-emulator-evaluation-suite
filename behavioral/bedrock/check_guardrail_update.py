"""guardrail-update."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", _unique_name("gr-"))
    kwargs.setdefault("blockedInputMessaging", "Input blocked by guardrail.")
    kwargs.setdefault("blockedOutputsMessaging", "Output blocked by guardrail.")
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp

CHECK = "guardrail-update"
GROUP = 'guardrails'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGuardrail changes the description; GetGuardrail reflects it."""
    bc = ctx.client("bedrock")
    create_resp = _create_guardrail(bc, ctx,
        description="original",
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": "sim2real-update-topic",
                    "definition": "Topic for update test",
                    "type": "DENY",
                }
            ]
        },
        tags=[{"key": "sim2real", "value": "guardrail-update"}])
    gid = create_resp["guardrailId"]
    name = bc.get_guardrail(guardrailIdentifier=gid)["name"]

    bc.update_guardrail(
        guardrailIdentifier=gid,
        name=name,
        description="updated-by-sim2real",
        blockedInputMessaging="blocked",
        blockedOutputsMessaging="blocked",
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": "sim2real-update-topic",
                    "definition": "Topic for update test",
                    "type": "DENY",
                }
            ]
        })
    get_resp = bc.get_guardrail(guardrailIdentifier=gid)
    assert get_resp["description"] == "updated-by-sim2real", (
        f"Expected description='updated-by-sim2real', got {get_resp['description']!r}"
    )
    assert get_resp["blockedInputMessaging"] == "blocked", (
        f"Expected blockedInputMessaging='blocked', got {get_resp['blockedInputMessaging']!r}"
    )
    assert get_resp["blockedOutputsMessaging"] == "blocked", (
        f"Expected blockedOutputsMessaging='blocked', got {get_resp['blockedOutputsMessaging']!r}"
    )
    assert get_resp["version"] == "DRAFT", (
        f"UpdateGuardrail with no guardrailVersion arg must move the DRAFT, not publish a "
        f"numbered version; got version={get_resp['version']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
