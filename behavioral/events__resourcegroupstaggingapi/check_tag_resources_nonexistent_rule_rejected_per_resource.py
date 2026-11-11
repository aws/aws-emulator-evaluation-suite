"""tag-resources-nonexistent-rule-rejected-per-resource."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "tag-resources-nonexistent-rule-rejected-per-resource"
GROUP = "overly-permissive"
SERVICES = ["events", "resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResources over one live and one absent EventBridge rule tags the live rule and reports
    only the absent one in FailedResourcesMap with EventBridge's ResourceNotFoundException.
    """
    events = ctx.client("events")
    rgt = ctx.client("resourcegroupstaggingapi")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]
    key = ctx.unique_name("sim2real-behav-part-")

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    live_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": ["sim2real.behav"]}),
        State="ENABLED",
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    ghost_name = ctx.unique_name("sim2real-behav-ghost-")
    ghost_arn = f"arn:aws:events:{ctx.region}:{account}:rule/{ghost_name}"

    result = rgt.tag_resources(ResourceARNList=[live_arn, ghost_arn], Tags={key: "partial"})

    failed = result["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the absent rule "
        f"{ghost_arn!r} -- the live rule {live_arn!r} must not fail and the absent one must not pass"
    )
    detail = failed[ghost_arn]
    assert detail["ErrorCode"] == "ResourceNotFoundException", (
        f"the per-resource ErrorCode for an absent rule was {detail['ErrorCode']!r}, expected "
        f"EventBridge's own ResourceNotFoundException"
    )
    assert detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {detail['StatusCode']!r}, expected 400"
    )
    expected_message = f"Rule {ghost_name} does not exist on EventBus default."
    assert detail["ErrorMessage"] == expected_message, (
        f"the per-resource ErrorMessage for an absent rule was {detail['ErrorMessage']!r}, "
        f"expected {expected_message!r}"
    )

    native_tags = _poll_until(
        lambda: {t["Key"]: t["Value"] for t in events.list_tags_for_resource(ResourceARN=live_arn)["Tags"]},
        lambda m: m.get(key) == "partial",
        timeout_s=180.0,
    )
    assert native_tags.get(key) == "partial", (
        f"the live rule {live_arn!r} never received {key}=partial (saw {native_tags!r}) -- a "
        f"partial failure must still apply the tags that succeeded"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
