"""get-default-patch-baseline-invalid-operating-system-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-default-patch-baseline-invalid-operating-system-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_OPERATING_SYSTEMS = (
    "RASPBIAN", "WINDOWS", "AMAZON_LINUX_2022", "AMAZON_LINUX_2023", "UBUNTU", "ROCKY_LINUX",
    "REDHAT_ENTERPRISE_LINUX", "CENTOS", "AMAZON_LINUX_2", "MACOS", "ORACLE_LINUX", "SUSE",
    "ALMA_LINUX", "DEBIAN", "AMAZON_LINUX",
)
_BAD_OS = "NOT_A_REAL_OS"
_UNKNOWN_ENUM = (
    "ValidationException",
    f"1 validation error detected: Value '{_BAD_OS}' at 'operatingSystem' failed to satisfy "
    "constraint: Member must satisfy enum value set: [" + ", ".join(_OPERATING_SYSTEMS) + "]",
)
_BASELINE_ID = re.compile(r"^arn:aws:ssm:[a-z0-9-]+:\d{12}:patchbaseline/pb-[a-zA-Z0-9]+$")


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) raised by ``fn``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDefaultPatchBaseline rejects an OperatingSystem outside the enum, naming every valid
    value, and returns the AWS-owned baseline for a modelled OperatingSystem."""
    ssm = ctx.client("ssm")

    got = _error(lambda: ssm.get_default_patch_baseline(OperatingSystem=_BAD_OS))
    assert got == _UNKNOWN_ENUM, f"expected {_UNKNOWN_ENUM!r}, got {got!r}"

    resp = ssm.get_default_patch_baseline(OperatingSystem="AMAZON_LINUX_2023")
    assert resp["OperatingSystem"] == "AMAZON_LINUX_2023", resp
    assert _BASELINE_ID.match(resp["BaselineId"]), f"unexpected BaselineId shape: {resp['BaselineId']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
