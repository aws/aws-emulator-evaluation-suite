"""guardrail-create-get-roundtrip."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

#: Bounded wait for a guardrail to reach a terminal status (the default service-class budget).
POLL_DEADLINE_S = 600.0

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", _unique_name("gr-"))
    kwargs.setdefault("blockedInputMessaging", "Input blocked by guardrail.")
    kwargs.setdefault("blockedOutputsMessaging", "Output blocked by guardrail.")
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: _delete_if_present(bc, resp["guardrailId"]))
    return resp


def _delete_if_present(bc, gid):
    """Teardown: delete the guardrail unless the body already deleted it."""
    try:
        bc.delete_guardrail(guardrailIdentifier=gid)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_ready(bc, gid):
    """Poll GetGuardrail to the terminal READY status; FAILED or the deadline raises."""
    deadline = time.monotonic() + POLL_DEADLINE_S
    while True:
        got = bc.get_guardrail(guardrailIdentifier=gid)
        if got["status"] == "READY":
            return got
        if got["status"] == "FAILED":
            raise AssertionError(f"guardrail reached FAILED: {got.get('failureRecommendations')!r}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"guardrail never reached READY (last status {got['status']!r})")
        time.sleep(2)


def _error(fn):
    """(code, HTTP status, message) of the ClientError *fn* raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["ResponseMetadata"]["HTTPStatusCode"],
                exc.response["Error"].get("Message", ""))
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _listed_ids(bc):
    """Every guardrail id ListGuardrails returns, following nextToken."""
    ids, kwargs = set(), {}
    while True:
        page = bc.list_guardrails(**kwargs)
        ids.update(g["id"] for g in page["guardrails"])
        if not page.get("nextToken"):
            return ids
        kwargs["nextToken"] = page["nextToken"]

CHECK = "guardrail-create-get-roundtrip"
GROUP = 'guardrails'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGuardrail -> READY, GetGuardrail returns consistent data -> UpdateGuardrail is
    reflected -> DeleteGuardrail -> Get not-found, unlisted, and an update is refused."""
    bc = ctx.client("bedrock")
    name = _unique_name("gr-")
    description = "Behavioral test guardrail"
    input_messaging = "Custom input-blocked message for roundtrip check."
    output_messaging = "Custom output-blocked message for roundtrip check."
    topic_name = "sim2real-blocked-topic"
    topic_definition = "Discussion of testing internals"
    create_resp = _create_guardrail(bc, ctx,
        name=name,
        description=description,
        blockedInputMessaging=input_messaging,
        blockedOutputsMessaging=output_messaging,
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": topic_name,
                    "definition": topic_definition,
                    "type": "DENY",
                }
            ]
        })
    gid = create_resp["guardrailId"]
    assert gid, f"CreateGuardrail returned no guardrailId: {create_resp}"
    expected_arn = f"arn:aws:bedrock:{ctx.region}:{ctx.account}:guardrail/{gid}"
    assert create_resp["guardrailArn"] == expected_arn, (
        f"Expected guardrailArn={expected_arn!r}, got {create_resp.get('guardrailArn')!r}"
    )

    get_resp = _wait_ready(bc, gid)
    assert get_resp["name"] == name, (
        f"Expected name={name!r}, got {get_resp['name']!r}"
    )
    assert get_resp["guardrailId"] == gid, (
        f"Expected guardrailId={gid!r}, got {get_resp['guardrailId']!r}"
    )
    assert get_resp["guardrailArn"] == create_resp["guardrailArn"], (
        f"Expected guardrailArn={create_resp['guardrailArn']!r}, got {get_resp['guardrailArn']!r}"
    )
    assert get_resp["description"] == description, (
        f"Expected description={description!r}, got {get_resp.get('description')!r}"
    )
    assert get_resp["blockedInputMessaging"] == input_messaging, (
        f"Expected blockedInputMessaging={input_messaging!r}, "
        f"got {get_resp.get('blockedInputMessaging')!r}"
    )
    assert get_resp["blockedOutputsMessaging"] == output_messaging, (
        f"Expected blockedOutputsMessaging={output_messaging!r}, "
        f"got {get_resp.get('blockedOutputsMessaging')!r}"
    )
    topics = get_resp["topicPolicy"]["topics"]
    matching = [t for t in topics if t["name"] == topic_name]
    assert len(matching) == 1, (
        f"Expected exactly one topic named {topic_name!r} in {topics}"
    )
    assert matching[0]["definition"] == topic_definition, (
        f"Expected topic definition={topic_definition!r}, got {matching[0]['definition']!r}"
    )
    assert matching[0]["type"] == "DENY", (
        f"Expected topic type='DENY', got {matching[0]['type']!r}"
    )

    topic_policy = {"topicsConfig": [{"name": topic_name, "definition": topic_definition, "type": "DENY"}]}
    new_description = "Behavioral test guardrail, updated"
    bc.update_guardrail(
        guardrailIdentifier=gid, name=name, description=new_description,
        blockedInputMessaging=input_messaging, blockedOutputsMessaging=output_messaging,
        topicPolicyConfig=topic_policy,
    )
    updated = _wait_ready(bc, gid)
    assert updated["description"] == new_description, (
        f"Expected the updated description={new_description!r}, got {updated.get('description')!r}"
    )

    assert gid in _listed_ids(bc), "the live guardrail must be listed before the delete"
    bc.delete_guardrail(guardrailIdentifier=gid)

    deadline = time.monotonic() + POLL_DEADLINE_S
    while True:
        try:
            bc.get_guardrail(guardrailIdentifier=gid)
        except ClientError as exc:
            gone_code = exc.response["Error"]["Code"]
            gone_status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
            gone_message = exc.response["Error"].get("Message", "")
            break
        if time.monotonic() >= deadline:
            raise AssertionError("GetGuardrail still answers for the deleted guardrail")
        time.sleep(2)
    assert (gone_code, gone_status) == ("ResourceNotFoundException", 404), (
        f"GetGuardrail on the deleted guardrail: expected ResourceNotFoundException/404, got {gone_code}/{gone_status}"
    )
    expected_message = "This guardrail does not exist."
    assert gone_message == expected_message, f"expected the message {expected_message!r}, got {gone_message!r}"

    assert gid not in _listed_ids(bc), "the deleted guardrail is still listed"

    dead_code, dead_status, dead_message = _error(lambda: bc.update_guardrail(
        guardrailIdentifier=gid, name=name, description="x",
        blockedInputMessaging=input_messaging, blockedOutputsMessaging=output_messaging,
        topicPolicyConfig=topic_policy,
    ))
    assert (dead_code, dead_status) == ("ResourceNotFoundException", 404), (
        f"UpdateGuardrail on the deleted guardrail: expected ResourceNotFoundException/404, got {dead_code}/{dead_status}"
    )
    expected_message = "This guardrail does not exist."
    assert dead_message == expected_message, f"expected the message {expected_message!r}, got {dead_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
