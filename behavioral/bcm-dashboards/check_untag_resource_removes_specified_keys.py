"""untag-resource-removes-specified-keys."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-specified-keys"
GROUP = "tagging"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes only the specified keys, leaving the rest of the tag set."""
    bcm = ctx.client("bcm-dashboards")
    name = ctx.unique_name("sim2real-dash-")
    arn = bcm.create_dashboard(
        name=name,
        widgets=[_cost_widget("W1")],
        resourceTags=[
            {"key": "keep-me", "value": "1"},
            {"key": "drop-me", "value": "2"},
        ],
    )["arn"]
    ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=arn))

    bcm.untag_resource(resourceArn=arn, resourceTagKeys=["drop-me"])

    tags = bcm.list_tags_for_resource(resourceArn=arn)["resourceTags"]
    by_key = {t["key"]: t["value"] for t in tags}
    assert "drop-me" not in by_key, by_key
    assert by_key.get("keep-me") == "1", by_key


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
