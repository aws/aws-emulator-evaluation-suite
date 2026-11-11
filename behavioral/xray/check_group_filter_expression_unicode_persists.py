"""group-filter-expression-unicode-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "group-filter-expression-unicode-persists"
GROUP = "representation"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A FilterExpression with accented, CJK and Greek characters comes back byte-identical from
    CreateGroup and GetGroup."""
    xray = ctx.client("xray")
    name = ctx.unique_name("sim2real-xray-grp-")
    # Accented latin, CJK, Greek, a BMP symbol and nested quoting in the filter grammar. X-Ray
    # refuses characters outside the Basic Multilingual Plane ("Invalid unicode xml character"),
    # so the expression stays inside it.
    filter_expr = (
        'service("caf\u00e9-\u65e5\u672c\u8a9e-\u03a9_test") '
        '{ fault = true } AND annotation.tag = "special-\u2603-value"'
    )

    created = xray.create_group(GroupName=name, FilterExpression=filter_expr)["Group"]
    ctx.on_cleanup(lambda: xray.delete_group(GroupName=name))

    assert created["GroupName"] == name, (
        f"CreateGroup returned GroupName {created['GroupName']!r}, expected {name!r}"
    )
    assert created["FilterExpression"] == filter_expr, (
        f"CreateGroup response mangled the filter expression: {created['FilterExpression']!r}"
    )

    fetched = xray.get_group(GroupName=name)["Group"]
    assert fetched["GroupName"] == name, (
        f"GetGroup returned GroupName {fetched['GroupName']!r}, expected {name!r}"
    )
    assert fetched["FilterExpression"] == filter_expr, (
        f"GetGroup returned a different filter expression than was stored: {fetched['FilterExpression']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
