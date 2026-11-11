"""describe-parameters-filters-by-type-and-tier."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-parameters-filters-by-type-and-tier"
GROUP = 'parameter-store'
SERVICES = ['ssm']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeParameters Type and Tier filters each narrow independently, and combined they AND
    (intersection, not union); results are scoped to this check's Name prefix.
    """
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-typetier-")
    std_string = f"{base}/std-string"
    std_list = f"{base}/std-list"
    adv_string = f"{base}/adv-string"

    for name in (std_string, std_list, adv_string):
        ctx.on_cleanup(lambda n=name: ssm.delete_parameter(Name=n))

    ssm.put_parameter(Name=std_string, Value="v1", Type="String", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ssm.put_parameter(Name=std_list, Value="a,b", Type="StringList", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ssm.put_parameter(Name=adv_string, Value="v3", Type="String", Tier="Advanced",
                      Tags=[{"Key": "sim2real", "Value": CHECK}])

    # DescribeParameters may return fewer than MaxResults items with a NextToken, so every
    # listing follows the pages to the end.
    def _all_pages(filters):
        pages = ssm.get_paginator("describe_parameters").paginate(ParameterFilters=filters)
        return [p for page in pages for p in page["Parameters"]]

    def _described(*filters):
        scoped = [{"Key": "Name", "Option": "BeginsWith", "Values": [base]}, *filters]
        return {p["Name"] for p in _all_pages(scoped)}

    everything = _described()
    assert everything == {std_string, std_list, adv_string}, (
        f"the Name/BeginsWith scope alone must list all three, got {sorted(everything)}"
    )

    by_type = _described({"Key": "Type", "Option": "Equals", "Values": ["StringList"]})
    assert by_type == {std_list}, (
        f"Type=Equals[StringList] must narrow to exactly {std_list!r}, got {sorted(by_type)}"
    )

    by_tier = _described({"Key": "Tier", "Option": "Equals", "Values": ["Advanced"]})
    assert by_tier == {adv_string}, (
        f"Tier=Equals[Advanced] must narrow to exactly {adv_string!r}, got {sorted(by_tier)}"
    )

    # Both filters together AND: String type AND Standard tier excludes the StringList
    # (wrong type) and the Advanced string (wrong tier), leaving only std_string.
    anded = _described(
        {"Key": "Type", "Option": "Equals", "Values": ["String"]},
        {"Key": "Tier", "Option": "Equals", "Values": ["Standard"]},
    )
    assert anded == {std_string}, (
        f"Type=String AND Tier=Standard must narrow to exactly {std_string!r} -- the "
        f"intersection, not the union -- got {sorted(anded)}"
    )

    # A combination that no member satisfies must narrow to the empty set, not fall back
    # to either filter alone.
    empty = _described(
        {"Key": "Type", "Option": "Equals", "Values": ["StringList"]},
        {"Key": "Tier", "Option": "Equals", "Values": ["Advanced"]},
    )
    assert empty == set(), (
        f"Type=StringList AND Tier=Advanced matches no created member, must be empty, "
        f"got {sorted(empty)}"
    )

    for name, tier in ((adv_string, "Advanced"), (std_string, "Standard")):
        described = _all_pages([{"Key": "Name", "Option": "Equals", "Values": [name]}])
        assert len(described) == 1, (
            f"DescribeParameters Name=Equals[{name}] must return exactly that parameter, "
            f"got {described}"
        )
        assert described[0]["Tier"] == tier, (
            f"DescribeParameters metadata for {name} must report Tier {tier}, got {described[0]}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
