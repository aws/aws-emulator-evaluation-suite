"""put-rule-update-replaces-omitted-fields-and-ignores-tags."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-rule-update-replaces-omitted-fields-and-ignores-tags"
GROUP = 'rule'
SERVICES = ['events']


def _tags(ev, arn: str) -> dict:
    return {t["Key"]: t["Value"] for t in ev.list_tags_for_resource(ResourceARN=arn)["Tags"]}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRule on an existing rule replaces it: the new pattern applies, omitted Description and
    State reset (State back to ENABLED), the ARN, targets and original tag survive, and update Tags
    are ignored.
    """
    ev = ctx.client("events")
    rule = ctx.unique_name("sim2real-behav-rule-")
    original_tags = {"sim2real": "behavioral"}
    created_arn = ev.put_rule(
        Name=rule,
        EventPattern=json.dumps({"source": ["sim2real.before"]}),
        Description="sim2real original description",
        State="DISABLED",
        Tags=[{"Key": k, "Value": v} for k, v in original_tags.items()],
    )["RuleArn"]
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))

    partition = created_arn.split(":")[1]
    target_arn = f"arn:{partition}:sqs:{ctx.region}:{ctx.account}:" + ctx.unique_name("sim2real-behav-q-")
    ev.put_targets(Rule=rule, Targets=[{"Id": "kept", "Arn": target_arn}])
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=["kept"]))

    before = ev.describe_rule(Name=rule)
    assert before["State"] == "DISABLED", f"the rule was created DISABLED but reads {before['State']!r}"
    assert before.get("Description") == "sim2real original description", (
        f"the rule's Description reads {before.get('Description')!r} after create"
    )

    updated_arn = ev.put_rule(
        Name=rule,
        EventPattern=json.dumps({"source": ["sim2real.after"]}),
        Tags=[{"Key": "sim2real-added-on-update", "Value": "ignored"}],
    )["RuleArn"]
    assert updated_arn == created_arn, "updating the rule changed its ARN"

    after = ev.describe_rule(Name=rule)
    assert json.loads(after["EventPattern"]) == {"source": ["sim2real.after"]}, (
        f"the updated rule's EventPattern is {after['EventPattern']!r}, expected source sim2real.after"
    )
    assert "Description" not in after, (
        f"an update that omitted Description kept {after.get('Description')!r}; PutRule replaces the rule"
    )
    assert after["State"] == "ENABLED", (
        f"an update that omitted State left the rule {after['State']!r}, expected the default ENABLED"
    )
    assert _tags(ev, created_arn) == original_tags, (
        f"after an update carrying a new tag the rule's tags are {_tags(ev, created_arn)!r}, "
        f"expected only {original_tags!r}"
    )
    kept = [t["Id"] for t in ev.list_targets_by_rule(Rule=rule)["Targets"]]
    assert kept == ["kept"], f"the rule's targets after the update are {kept!r}, expected ['kept']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
