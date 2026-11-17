"""describe-option-groups-major-engine-version-without-engine-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-option-groups-major-engine-version-without-engine-name-rejected"
GROUP = "option_groups"
SERVICES = ["rds"]

_NEEDS_ENGINE_NAME = (
    "InvalidParameterCombination",
    "If MajorEngineVersion is specified, then EngineName must also be specified.",
)


def _error(fn):
    """The (Code, Message) ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeOptionGroups with MajorEngineVersion but no EngineName is rejected; the
    same MajorEngineVersion filter paired with EngineName finds the group it was aimed at.
    """
    rds = ctx.client("rds")
    version = rds.describe_db_engine_versions(
        Engine="mysql", DefaultOnly=True
    )["DBEngineVersions"][0]["MajorEngineVersion"]

    name = ctx.unique_name("sim2real-behav-og-")
    rds.create_option_group(
        OptionGroupName=name,
        EngineName="mysql",
        MajorEngineVersion=version,
        OptionGroupDescription="sim2real behavioral engine-version filter test group",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=name))

    code, message = _error(lambda: rds.describe_option_groups(MajorEngineVersion=version))
    assert (code, message) == _NEEDS_ENGINE_NAME, (code, message)

    # Positive control: the legal neighbor of the refused call — the same MajorEngineVersion
    # filter, paired with EngineName — succeeds and finds the group it was aimed at.
    pages = rds.get_paginator("describe_option_groups").paginate(
        EngineName="mysql", MajorEngineVersion=version
    )
    names = [g["OptionGroupName"] for page in pages for g in page["OptionGroupsList"]]
    assert name in names, (name, names)

    direct = rds.describe_option_groups(OptionGroupName=name)["OptionGroupsList"]
    assert len(direct) == 1, direct
    assert direct[0]["EngineName"] == "mysql", direct[0]
    assert direct[0]["MajorEngineVersion"] == version, direct[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
