"""delete-nonexistent-option-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-option-group"
GROUP = 'errors'
SERVICES = ['rds']

ERR_OPTION_GROUP_NOT_FOUND = "OptionGroupNotFoundFault"


def _delete_unless_gone(delete, gone_code):
    """Teardown delete; an already-deleted resource answers ``gone_code`` (documented not-found)."""
    try:
        delete()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteOptionGroup for nonexistent raises NotFound; a real option group's delete
    still succeeds (positive control), so the rejection is specific to absence and not
    every DeleteOptionGroup call."""
    rds = ctx.client("rds")

    # --- positive control: delete of a real, just-created option group succeeds ---
    real_name = ctx.unique_name("sim2real-behav-og-")
    rds.create_option_group(
        OptionGroupName=real_name,
        EngineName="mysql",
        MajorEngineVersion="8.0",
        OptionGroupDescription="sim2real behavioral test option group",
    )
    ctx.on_cleanup(lambda: _delete_unless_gone(
        lambda: rds.delete_option_group(OptionGroupName=real_name), "OptionGroupNotFoundFault"))
    rds.delete_option_group(OptionGroupName=real_name)

    ghost = ctx.unique_name("sim2real-behav-og-")
    try:
        rds.delete_option_group(OptionGroupName=ghost)
        code = message = None
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_OPTION_GROUP_NOT_FOUND, (
        f"expected {ERR_OPTION_GROUP_NOT_FOUND}, got {code!r}"
    )
    assert message == f"Specified OptionGroupName: {ghost} not found.", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
