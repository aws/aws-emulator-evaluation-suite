"""describe-patch-group-state-rejects-disallowed-characters."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-patch-group-state-rejects-disallowed-characters"
GROUP = "validation"
SERVICES = ["ssm"]


def _error_code(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribePatchGroupState rejects a PatchGroup name containing a character outside its
    modeled pattern, while the same name without that character succeeds."""
    ssm = ctx.client("ssm")
    base_name = ctx.unique_name("sim2real-patchgroup-")

    control = ssm.describe_patch_group_state(PatchGroup=base_name)
    assert control["Instances"] == 0, control

    bad_name = base_name + "#bad"
    code, message = _error_code(
        lambda: ssm.describe_patch_group_state(PatchGroup=bad_name)
    )
    assert code == "ValidationException", code
    assert message == (
        f"1 validation error detected: Value '{bad_name}' at 'patchGroup' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "^([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)$"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
