"""register-default-patch-baseline-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-default-patch-baseline-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]

_OS = "AMAZON_LINUX_2"


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator accepting a BaselineId real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(
        f"real AWS rejects RegisterDefaultPatchBaseline for a nonexistent BaselineId, "
        f"but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ssm-default-patch-baseline")
def run(ctx) -> None:
    """RegisterDefaultPatchBaseline with a nonexistent BaselineId fails with DoesNotExistException "Patch Baseline
    to be retrieved does not exist." and leaves the default unchanged, while a real baseline registers as
    default."""
    ssm = ctx.client("ssm")

    original_default_id = ssm.get_default_patch_baseline(OperatingSystem=_OS)["BaselineId"]

    bogus_baseline_id = "pb-00000000000000000"
    code, message = _client_error(
        lambda: ssm.register_default_patch_baseline(BaselineId=bogus_baseline_id)
    )
    assert code == "DoesNotExistException", f"expected DoesNotExistException, got {code!r}"
    assert message == "Patch Baseline to be retrieved does not exist.", f"unexpected message {message!r}"

    unchanged_default_id = ssm.get_default_patch_baseline(OperatingSystem=_OS)["BaselineId"]
    assert unchanged_default_id == original_default_id, (
        f"expected default baseline to remain {original_default_id!r} after the "
        f"rejected registration, got {unchanged_default_id!r}"
    )

    # Positive control: a real baseline can be registered as default, then reverted.
    new_baseline_id = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-defaultpb-neg-"),
        OperatingSystem=_OS,
        ApprovalRules={
            "PatchRules": [
                {
                    "PatchFilterGroup": {
                        "PatchFilters": [
                            {"Key": "CLASSIFICATION", "Values": ["Security"]}
                        ]
                    },
                    "ApproveAfterDays": 7,
                }
            ]
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=new_baseline_id))
    ctx.on_cleanup(lambda: ssm.register_default_patch_baseline(BaselineId=original_default_id))

    ssm.register_default_patch_baseline(BaselineId=new_baseline_id)
    current = ssm.get_default_patch_baseline(OperatingSystem=_OS)["BaselineId"]
    assert current == new_baseline_id, f"expected default baseline {new_baseline_id!r}, got {current!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
