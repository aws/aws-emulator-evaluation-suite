"""describe-parameters-tag-filter-requires-exact-value-despite-beginswith-option."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-parameters-tag-filter-requires-exact-value-despite-beginswith-option"
GROUP = 'representation'
SERVICES = ['ssm']


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A tag:<key> DescribeParameters filter under Option=BeginsWith matches only the exact value,
    not a strict prefix of it: it behaves like Option=Equals."""
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-tagprefix-")
    name = f"{base}/p"
    tag_value = "sim2real-tagprefix-test"
    strict_prefix = tag_value[:-5]
    assert strict_prefix != tag_value and tag_value.startswith(strict_prefix), (
        strict_prefix, tag_value,
    )

    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    ssm.put_parameter(Name=name, Value="v", Type="String", Tags=[{"Key": "env", "Value": tag_value}])

    def _described(tag_filter):
        # DescribeParameters may return fewer than MaxResults items with a NextToken, so the
        # listing follows the pages to the end.
        scoped = [{"Key": "Name", "Option": "Equals", "Values": [name]}, tag_filter]
        pages = ssm.get_paginator("describe_parameters").paginate(ParameterFilters=scoped)
        return [p["Name"] for page in pages for p in page["Parameters"]]

    # The exact value matches under both options, so an empty strict-prefix result means no prefix
    # matching rather than a missing parameter.
    exact_via_equals = _described({"Key": "tag:env", "Option": "Equals", "Values": [tag_value]})
    assert exact_via_equals == [name], (
        f"tag:env Equals[{tag_value!r}] (the exact value) must match, got {exact_via_equals}"
    )

    exact_via_beginswith = _described({"Key": "tag:env", "Option": "BeginsWith", "Values": [tag_value]})
    assert exact_via_beginswith == [name], (
        f"tag:env BeginsWith[{tag_value!r}] (the exact value, submitted under BeginsWith) "
        f"must still match -- the option does not refuse the exact value; got "
        f"{exact_via_beginswith}"
    )

    prefix_via_beginswith = _described({"Key": "tag:env", "Option": "BeginsWith", "Values": [strict_prefix]})
    assert prefix_via_beginswith == [], (
        f"tag:env BeginsWith[{strict_prefix!r}], a genuine strict prefix of the tag value "
        f"{tag_value!r}, must NOT match -- Option=BeginsWith on a tag: key does not unlock "
        f"prefix matching, contrary to what its name suggests; got {prefix_via_beginswith}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
