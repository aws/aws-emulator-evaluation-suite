"""global-infrastructure-region-public-parameters-name-us-east-1."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "global-infrastructure-region-public-parameters-name-us-east-1"
GROUP = "parameter-store"
SERVICES = ["ssm"]

_REGIONS = "/aws/service/global-infrastructure/regions"
_LONG_NAME = (f"{_REGIONS}/us-east-1/longName", "US East (N. Virginia)")


@tags(
    "axis:happy-path",
    "cap:c5",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """The public global-infrastructure regions parameters list and name each Region.

    Each Region parameter's value is its code; us-east-1's longName is "US East (N. Virginia)".
    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-public-parameters-global-infrastructure.html
    """
    ssm = ctx.client("ssm")

    regions = {
        p["Name"]: (p["Type"], p["Value"])
        for page in ssm.get_paginator("get_parameters_by_path").paginate(Path=_REGIONS)
        for p in page["Parameters"]
    }
    for code in ("us-east-1", "us-west-2"):
        name = f"{_REGIONS}/{code}"
        assert regions.get(name) == ("String", code), (
            f"GetParametersByPath {_REGIONS} must list {name} as a String whose value is {code!r}; "
            f"got {regions.get(name)!r} among {len(regions)} parameters"
        )

    long_name = ssm.get_parameter(Name=_LONG_NAME[0])["Parameter"]
    assert (long_name["Name"], long_name["Value"]) == _LONG_NAME, (
        f"GetParameter {_LONG_NAME[0]} must return {_LONG_NAME[1]!r}; got "
        f"({long_name['Name']!r}, {long_name['Value']!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
