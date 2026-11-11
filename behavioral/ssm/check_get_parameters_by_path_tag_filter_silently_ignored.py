"""get-parameters-by-path-tag-filter-silently-ignored."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-parameters-by-path-tag-filter-silently-ignored"
GROUP = 'representation'
SERVICES = ['ssm']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetParametersByPath accepts a tag:<key> filter but ignores it (a matching and a
    non-matching value both return the full subtree), while DescribeParameters honours it."""
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-tagsilent-")
    tagged = f"{base}/tagged"
    untagged = f"{base}/untagged"

    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=tagged))
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=untagged))
    ssm.put_parameter(Name=tagged, Value="v-tagged", Type="String",
                       Tags=[{"Key": "env", "Value": "sim2real-tagsilent"}])
    ssm.put_parameter(Name=untagged, Value="v-untagged", Type="String")

    baseline = ssm.get_parameters_by_path(Path=base, Recursive=True)["Parameters"]
    assert {p["Name"] for p in baseline} == {tagged, untagged}, (
        f"the unfiltered subtree must contain both members, got "
        f"{sorted(p['Name'] for p in baseline)}"
    )

    matching_tag = {"Key": "tag:env", "Option": "Equals", "Values": ["sim2real-tagsilent"]}
    no_such_tag = {"Key": "tag:env", "Option": "Equals", "Values": ["no-such-value"]}

    by_matching_tag = ssm.get_parameters_by_path(
        Path=base, Recursive=True, ParameterFilters=[matching_tag]
    )["Parameters"]
    by_no_such_tag = ssm.get_parameters_by_path(
        Path=base, Recursive=True, ParameterFilters=[no_such_tag]
    )["Parameters"]

    assert {p["Name"] for p in by_matching_tag} == {tagged, untagged}, (
        "a tag: filter whose value MATCHES the tagged member must not be rejected, but "
        f"it must also not narrow the subtree (GetParametersByPath does not honor tag: "
        f"filters); got {sorted(p['Name'] for p in by_matching_tag)}"
    )
    assert {p["Name"] for p in by_no_such_tag} == {tagged, untagged}, (
        "a tag: filter whose value matches NOTHING must still return the full subtree "
        f"unchanged -- it is a silent no-op, not a narrowing filter; got "
        f"{sorted(p['Name'] for p in by_no_such_tag)}"
    )

    # Contrast: the identical tag: filter DOES narrow DescribeParameters, scoped to this
    # path with a Name filter so the assertion is a property of the query, not of the
    # account's other contents. A page may hold fewer than MaxResults items with a NextToken,
    # so each listing follows the pages to the end.
    described_matching = [
        p
        for page in ssm.get_paginator("describe_parameters").paginate(
            ParameterFilters=[
                {"Key": "Name", "Option": "BeginsWith", "Values": [base]},
                matching_tag,
            ]
        )
        for p in page["Parameters"]
    ]
    assert [p["Name"] for p in described_matching] == [tagged], (
        "DescribeParameters DOES honor the tag: filter -- the asymmetry with "
        f"GetParametersByPath is real, not an artifact of this check; got "
        f"{[p['Name'] for p in described_matching]}"
    )
    described_no_such = [
        p
        for page in ssm.get_paginator("describe_parameters").paginate(
            ParameterFilters=[
                {"Key": "Name", "Option": "BeginsWith", "Values": [base]},
                no_such_tag,
            ]
        )
        for p in page["Parameters"]
    ]
    assert described_no_such == [], (
        f"DescribeParameters with a non-matching tag: value must narrow to nothing, got "
        f"{[p['Name'] for p in described_no_such]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
