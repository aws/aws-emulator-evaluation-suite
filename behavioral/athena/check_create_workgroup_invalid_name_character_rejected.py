"""create-workgroup-invalid-name-character-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-workgroup-invalid-name-character-rejected"
GROUP = "workgroup"
SERVICES = ["athena"]

_INVALID_NAME = (
    "InvalidRequestException",
    "1 validation error detected: Value at 'name' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: [a-zA-Z0-9._-]{1,128}",
)


def expect_error(fn, code, message):
    """Call fn(); assert it raises exactly (code, message). An unexpected SUCCESS raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected {code}, got {err.get('Code')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWorkGroup rejects a Name containing a character outside [a-zA-Z0-9._-] and creates
    nothing, while the same name with the character removed succeeds (positive control)."""
    athena = ctx.client("athena")
    base = ctx.unique_name("sim2real-behav-wg-")
    bad_name = base + "!"

    expect_error(lambda: athena.create_work_group(Name=bad_name), *_INVALID_NAME)

    names = {wg["Name"] for wg in athena.list_work_groups()["WorkGroups"]}
    assert bad_name not in names, f"rejected name {bad_name!r} must not appear in ListWorkGroups"

    athena.create_work_group(Name=base)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=base, RecursiveDeleteOption=True))
    created = athena.get_work_group(WorkGroup=base)["WorkGroup"]
    assert created["Name"] == base, f"expected Name={base!r}, got {created['Name']!r}"
    assert created["State"] == "ENABLED", f"expected State='ENABLED', got {created['State']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
