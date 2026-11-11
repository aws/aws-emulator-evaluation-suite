"""patch-baseline-amazon-linux-2023-echo-and-invalid-filter-key-rejected."""

from __future__ import annotations

import datetime
import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "patch-baseline-amazon-linux-2023-echo-and-invalid-filter-key-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


def _error(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _rules(filters):
    return {
        "PatchRules": [
            {
                "PatchFilterGroup": {"PatchFilters": filters},
                "ApproveAfterDays": 7,
                "ComplianceLevel": "CRITICAL",
            }
        ]
    }


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """GetPatchBaseline echoes an AMAZON_LINUX_2023 baseline exactly, with the defaults AWS fills.

    A patch filter key the operating system does not support is refused with its exact message.
    """
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-pbal2023-")
    filters = [
        {"Key": "CLASSIFICATION", "Values": ["Security"]},
        {"Key": "SEVERITY", "Values": ["Critical", "Important"]},
    ]
    baseline_id = ssm.create_patch_baseline(
        Name=name,
        OperatingSystem="AMAZON_LINUX_2023",
        Description="security patches after seven days",
        ApprovalRules=_rules(filters),
        ApprovedPatches=["openssl"],
        ApprovedPatchesComplianceLevel="HIGH",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))
    assert re.fullmatch(r"pb-[0-9a-f]{17}", baseline_id), (
        f"BaselineId {baseline_id!r} has an unexpected form"
    )

    got = ssm.get_patch_baseline(BaselineId=baseline_id)
    created, modified = got.pop("CreatedDate"), got.pop("ModifiedDate")
    got.pop("ResponseMetadata")
    assert isinstance(created, datetime.datetime), f"CreatedDate is {created!r}"
    assert modified == created, f"ModifiedDate {modified!r} differs from CreatedDate {created!r}"
    expected = {
        "BaselineId": baseline_id,
        "Name": name,
        "OperatingSystem": "AMAZON_LINUX_2023",
        "Description": "security patches after seven days",
        "GlobalFilters": {"PatchFilters": []},
        "ApprovalRules": {
            "PatchRules": [
                {
                    "PatchFilterGroup": {"PatchFilters": filters},
                    "ComplianceLevel": "CRITICAL",
                    "ApproveAfterDays": 7,
                    "EnableNonSecurity": False,
                }
            ]
        },
        "ApprovedPatches": ["openssl"],
        "ApprovedPatchesComplianceLevel": "HIGH",
        "ApprovedPatchesEnableNonSecurity": False,
        "RejectedPatches": [],
        "RejectedPatchesAction": "ALLOW_AS_DEPENDENCY",
        "PatchGroups": [],
        "Sources": [],
    }
    assert got == expected, f"GetPatchBaseline returned {got!r}, expected {expected!r}"

    bad_name = ctx.unique_name("sim2real-behav-pbbad-")

    def create_bad():
        resp = ssm.create_patch_baseline(
            Name=bad_name,
            OperatingSystem="AMAZON_LINUX_2023",
            ApprovalRules=_rules([{"Key": "MSRC_SEVERITY", "Values": ["Critical"]}]),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=resp["BaselineId"]))
        return resp

    code, message = _error(create_bad)
    assert (code, message) == (
        "ValidationException",
        "Unknown Filter Key: MSRC_SEVERITY",
    ), f"CreatePatchBaseline with an unsupported filter key gave {code!r}: {message!r}"
    listed = ssm.describe_patch_baselines(Filters=[{"Key": "NAME_PREFIX", "Values": [bad_name]}])[
        "BaselineIdentities"
    ]
    assert listed == [], f"a refused CreatePatchBaseline left {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
