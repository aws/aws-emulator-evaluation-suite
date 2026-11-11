"""delete-grouping-configuration-removes-configuration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-grouping-configuration-removes-configuration"
GROUP = "lifecycle"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:application-signals-grouping-configuration")
def run(ctx) -> None:
    """Account grouping config: configured (Put) -> removed (Delete), observed via List. The
    configuration is an account-wide singleton, so cleanup restores whatever pre-existed."""
    sig = ctx.client("application-signals")
    grouping_name = "Sim2RealTeam" + ctx.unique_name("").replace("-", "")[:20]

    original = _list_all(sig)
    ctx.on_cleanup(lambda: _restore(sig, original))

    sig.put_grouping_configuration(
        GroupingAttributeDefinitions=[
            {
                "GroupingName": grouping_name,
                "GroupingSourceKeys": ["team"],
                "DefaultGroupingValue": "unknown",
            }
        ]
    )

    configured = sig.list_grouping_attribute_definitions()["GroupingAttributeDefinitions"]
    names = [d["GroupingName"] for d in configured]
    assert grouping_name in names, f"expected {grouping_name!r} in configured groupings, got {names!r}"

    sig.delete_grouping_configuration()

    removed = sig.list_grouping_attribute_definitions()["GroupingAttributeDefinitions"]
    assert removed == [], f"expected no grouping definitions after delete, got {removed!r}"


def _list_all(sig):
    definitions = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = sig.list_grouping_attribute_definitions(**kwargs)
        definitions.extend(resp["GroupingAttributeDefinitions"])
        next_token = resp.get("NextToken")
        if not next_token:
            return definitions


def _restore(sig, original):
    if original:
        sig.put_grouping_configuration(
            GroupingAttributeDefinitions=[
                {k: v for k, v in d.items() if k in ("GroupingName", "GroupingSourceKeys", "DefaultGroupingValue")}
                for d in original
            ]
        )
    else:
        sig.delete_grouping_configuration()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
