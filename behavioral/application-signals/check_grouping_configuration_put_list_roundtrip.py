"""grouping-configuration-put-list-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "grouping-configuration-put-list-roundtrip"
GROUP = "data-plane"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:application-signals-grouping-configuration")
def run(ctx) -> None:
    """PutGroupingConfiguration persists the exact GroupingSourceKeys and DefaultGroupingValue,
    round-tripped through ListGroupingAttributeDefinitions. The configuration is an account-wide
    singleton, so cleanup restores whatever pre-existed."""
    sig = ctx.client("application-signals")
    suffix = ctx.unique_name("").replace("-", "")[:16]
    grouping_name = f"Sim2RealBusinessUnit{suffix}"

    original = _list_all(sig)
    ctx.on_cleanup(lambda: _restore(sig, original))

    sig.put_grouping_configuration(
        GroupingAttributeDefinitions=[
            {
                "GroupingName": grouping_name,
                "GroupingSourceKeys": ["business_unit", "team"],
                "DefaultGroupingValue": "unassigned",
            }
        ]
    )

    definitions = _list_all(sig)
    match = next((d for d in definitions if d["GroupingName"] == grouping_name), None)
    assert match is not None, f"expected {grouping_name!r} among the grouping definitions, got {definitions!r}"
    assert match["GroupingSourceKeys"] == ["business_unit", "team"], (
        f"expected GroupingSourceKeys ['business_unit', 'team'], got {match['GroupingSourceKeys']!r}"
    )
    assert match["DefaultGroupingValue"] == "unassigned", (
        f"expected DefaultGroupingValue 'unassigned', got {match['DefaultGroupingValue']!r}"
    )


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
