"""tag-resource-exceeds-tag-limit-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-tag-limit-rejected"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with 60 tags on a guardrail (over the 50-per-resource limit, under the 200-item
    shape limit) returns TooManyTagsException 'You can assign a maximum of 50 tags to a resource' and
    persists no tag, while a single tag is accepted and listed."""
    bedrock = ctx.client("bedrock")
    guardrail = _create_guardrail(ctx, bedrock)

    # 200 items is the max the request shape itself allows (violating that
    # yields a plain ValidationException); 60 is comfortably over the
    # documented 50-tags-per-resource business limit while staying under the
    # shape's array-size cap, so this exercises TooManyTagsException instead.
    too_many_tags = [{"key": f"k{i}", "value": f"v{i}"} for i in range(60)]
    code, message = _error(
        lambda: bedrock.tag_resource(
            resourceARN=guardrail["arn"], tags=too_many_tags
        )
    )
    assert code == "TooManyTagsException", (
        f"expected TooManyTagsException for a 60-tag TagResource call, got {code!r}: {message!r}"
    )
    assert message == "You can assign a maximum of 50 tags to a resource", f"unexpected rejection message: {message!r}"

    # Effect absent: no tags were persisted by the rejected call.
    tags_after_bad = bedrock.list_tags_for_resource(resourceARN=guardrail["arn"])["tags"]
    assert tags_after_bad == [], (
        f"expected no tags after the rejected 60-tag call, found {tags_after_bad!r}"
    )

    # Positive control: a single valid tag is accepted and visible.
    bedrock.tag_resource(
        resourceARN=guardrail["arn"], tags=[{"key": "env", "value": "sim2real"}]
    )
    tags_after_good = bedrock.list_tags_for_resource(resourceARN=guardrail["arn"])["tags"]
    assert {"key": "env", "value": "sim2real"} in tags_after_good, (
        f"expected {{'key': 'env', 'value': 'sim2real'}} among tags after the within-quota "
        f"TagResource call, got {tags_after_good!r}"
    )


def _create_guardrail(ctx, bedrock: Any) -> dict[str, str]:
    name = ctx.unique_name("sim2real-bedrock-gr-")
    resp = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="Blocked by guardrail policy.",
        blockedOutputsMessaging="Blocked by guardrail policy.",
        contentPolicyConfig={
            "filtersConfig": [
                {"type": "SEXUAL", "inputStrength": "HIGH", "outputStrength": "HIGH"}
            ]
        },
    )
    guardrail_id = resp["guardrailId"]
    guardrail_arn = resp["guardrailArn"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))
    _wait_guardrail_status(bedrock, guardrail_id, {"READY"})
    return {"id": guardrail_id, "arn": guardrail_arn}


def _wait_guardrail_status(
    bedrock: Any,
    guardrail_id: str,
    target_statuses: set[str],
    timeout_s: float = 120.0,
    interval_s: float = 3.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        last_status = resp["status"]
        if last_status in target_statuses:
            return resp
        time.sleep(interval_s)
    raise AssertionError(
        f"guardrail {guardrail_id} did not reach {target_statuses}, last status {last_status}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn() and return its error (code, message); a success raises, as the call must be refused."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
