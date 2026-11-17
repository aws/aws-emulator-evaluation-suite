"""modify-option-group-not-found-after-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-option-group-not-found-after-delete"
GROUP = "option_groups"
SERVICES = ["rds"]

ERR_OPTION_GROUP_NOT_FOUND = "OptionGroupNotFoundFault"


def _error_code(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyOptionGroup on an option group deleted moments ago is rejected with
    OptionGroupNotFoundFault, the same call having succeeded while the group still existed."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-og-")
    rds.create_option_group(
        OptionGroupName=name,
        EngineName="mysql",
        MajorEngineVersion="8.0",
        OptionGroupDescription="sim2real behavioral check",
    )
    ctx.on_cleanup(lambda: _delete_unless_gone(rds, name))

    # Positive control: ModifyOptionGroup succeeds while the group exists.
    modified = rds.modify_option_group(
        OptionGroupName=name,
        OptionsToInclude=[{"OptionName": "MARIADB_AUDIT_PLUGIN"}],
        ApplyImmediately=True,
    )["OptionGroup"]
    option_names = {o["OptionName"] for o in modified["Options"]}
    assert "MARIADB_AUDIT_PLUGIN" in option_names, (
        f"expected MARIADB_AUDIT_PLUGIN among options after modify, got {option_names!r}"
    )

    rds.delete_option_group(OptionGroupName=name)
    gone_code, gone_message = _error_code(lambda: rds.describe_option_groups(OptionGroupName=name))
    assert gone_code == ERR_OPTION_GROUP_NOT_FOUND, f"unexpected error code after delete: {gone_code!r}"
    assert gone_message == f"Specified OptionGroupName: {name} not found.", gone_message

    code, message = _error_code(
        lambda: rds.modify_option_group(
            OptionGroupName=name,
            OptionsToInclude=[{"OptionName": "MARIADB_AUDIT_PLUGIN"}],
            ApplyImmediately=True,
        )
    )
    assert code == ERR_OPTION_GROUP_NOT_FOUND, f"unexpected error code: {code!r}"
    expected = f"Specified OptionGroupName: {name} not found."
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"


def _delete_unless_gone(rds, name: str) -> None:
    try:
        rds.delete_option_group(OptionGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != ERR_OPTION_GROUP_NOT_FOUND:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
