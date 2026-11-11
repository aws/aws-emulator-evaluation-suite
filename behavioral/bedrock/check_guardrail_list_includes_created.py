"""guardrail-list-includes-created."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", _unique_name("gr-"))
    kwargs.setdefault("blockedInputMessaging", "Input blocked by guardrail.")
    kwargs.setdefault("blockedOutputsMessaging", "Output blocked by guardrail.")
    kwargs.setdefault("tags", [{"key": "sim2real", "value": CHECK}])
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp


def _list_guardrails(bc):
    """Every guardrail visible to the caller, following nextToken to the terminal page.

    A bare single-page list_guardrails() can miss a just-created guardrail once the account
    already holds more than one page.
    """
    items, token = [], None
    while True:
        kw = {"maxResults": 100}
        if token:
            kw["nextToken"] = token
        page = bc.list_guardrails(**kw)
        items.extend(page.get("guardrails") or [])
        token = page.get("nextToken")
        if not token:
            return items

CHECK = "guardrail-list-includes-created"
GROUP = 'guardrails'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After creating a guardrail, ListGuardrails includes it with matching identity."""
    bc = ctx.client("bedrock")
    name = _unique_name("gr-")
    create_resp = _create_guardrail(bc, ctx,
        name=name,
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": "sim2real-test-topic",
                    "definition": "Blocked test topic",
                    "type": "DENY",
                }
            ]
        })
    gid = create_resp["guardrailId"]
    arn = create_resp["guardrailArn"]

    guardrails = _list_guardrails(bc)
    by_id = {g["id"]: g for g in guardrails}
    assert gid in by_id, (
        f"Created guardrail {gid} not found in list. IDs: {[g['id'] for g in guardrails][:10]}"
    )
    listed = by_id[gid]
    assert listed["name"] == name, f"listed name {listed['name']!r} != created name {name!r}"
    assert listed["arn"] == arn, f"listed arn {listed['arn']!r} != created arn {arn!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
