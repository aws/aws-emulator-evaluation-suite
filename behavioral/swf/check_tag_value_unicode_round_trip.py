"""tag-value-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag keys/values with unicode and allowed special characters survive Tag/ListTags unchanged."""
    swf = ctx.client("swf")
    domain = _register_domain(ctx)
    arn = swf.describe_domain(name=domain)["domainInfo"]["arn"]

    # SWF tags may contain unicode letters, digits, whitespace, or the symbols _.:/=+-@
    # (emoji and other punctuation are rejected), so exercise that exact allowed alphabet.
    tags = [
        {"key": "ключ_日本語:Ω", "value": "значение.тест/日本=ok+1-测试@x"},
        {"key": "plain key", "value": "plain value"},
    ]
    swf.tag_resource(resourceArn=arn, tags=tags)

    listed = swf.list_tags_for_resource(resourceArn=arn)["tags"]
    listed_map = {t["key"]: t["value"] for t in listed}
    for tag in tags:
        assert tag["key"] in listed_map, f"tag key {tag['key']!r} missing after round-trip"
        assert listed_map[tag["key"]] == tag["value"], (
            f"tag value for {tag['key']!r} not preserved: {listed_map[tag['key']]!r} != {tag['value']!r}"
        )


def _register_domain(ctx) -> str:
    swf = ctx.client("swf")
    name = ctx.unique_name("sim2real-swf-dom-")
    swf.register_domain(name=name, workflowExecutionRetentionPeriodInDays="1")
    # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
    ctx.on_cleanup(lambda: swf.deprecate_domain(name=name))
    arn = swf.describe_domain(name=name)["domainInfo"]["arn"]
    swf.tag_resource(resourceArn=arn, tags=[{"key": "sim2real-check", "value": CHECK}])
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
