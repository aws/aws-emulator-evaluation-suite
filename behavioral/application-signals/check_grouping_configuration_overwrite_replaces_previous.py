"""grouping-configuration-overwrite-replaces-previous."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "grouping-configuration-overwrite-replaces-previous"
GROUP = "state"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:application-signals-grouping-configuration")
def run(ctx) -> None:
    """PutGroupingConfiguration is a replacing PUT: a second call with different attribute
    definitions replaces the first set rather than merging with it. The configuration is an
    account-wide singleton, so cleanup restores whatever pre-existed."""
    sig = ctx.client("application-signals")
    suffix = ctx.unique_name("").replace("-", "")[:16]
    first_name = f"Sim2RealFirst{suffix}"
    second_name = f"Sim2RealSecond{suffix}"

    original = _list_all(sig)
    ctx.on_cleanup(lambda: _restore(sig, original))

    sig.put_grouping_configuration(
        GroupingAttributeDefinitions=[
            {"GroupingName": first_name, "GroupingSourceKeys": ["team"]}
        ]
    )

    after_first = {d["GroupingName"] for d in _list_all(sig)}
    assert after_first == {first_name}, f"expected only {first_name!r} after first put, got {after_first!r}"

    sig.put_grouping_configuration(
        GroupingAttributeDefinitions=[
            {"GroupingName": second_name, "GroupingSourceKeys": ["business_unit"]}
        ]
    )

    after_second = {d["GroupingName"] for d in _list_all(sig)}
    assert after_second == {second_name}, (
        f"expected only {second_name!r} after second put, got {after_second!r}"
    )
    assert first_name not in after_second, (
        f"{first_name!r} from the first put should have been replaced, not merged; got {after_second!r}"
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
