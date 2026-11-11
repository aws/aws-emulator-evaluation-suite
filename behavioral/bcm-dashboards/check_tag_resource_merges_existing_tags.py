"""tag-resource-merges-existing-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-merges-existing-tags"
GROUP = "tagging"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges the new tag into the existing tag set instead of replacing it:
    tagging with a second, disjoint key leaves the first key's tag intact."""
    bcm = ctx.client("bcm-dashboards")
    name = ctx.unique_name("sim2real-dash-")
    arn = bcm.create_dashboard(
        name=name,
        widgets=[_cost_widget("W1")],
        resourceTags=[{"key": "team", "value": "billing"}],
    )["arn"]
    ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=arn))

    bcm.tag_resource(resourceArn=arn, resourceTags=[{"key": "stage", "value": "test"}])

    tags = bcm.list_tags_for_resource(resourceArn=arn)["resourceTags"]
    by_key = {t["key"]: t["value"] for t in tags}
    assert by_key.get("team") == "billing", by_key
    assert by_key.get("stage") == "test", by_key


def _cost_widget(title: str) -> dict:
    return {
        "title": title,
        "configs": [
            {
                "queryParameters": {
                    "costAndUsage": {
                        "metrics": ["UnblendedCost"],
                        "timeRange": {
                            "startTime": {"type": "RELATIVE", "value": "-P1M"},
                            "endTime": {"type": "RELATIVE", "value": "-P0D"},
                        },
                        "granularity": "MONTHLY",
                    }
                },
                "displayConfig": {"table": {}},
            }
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
