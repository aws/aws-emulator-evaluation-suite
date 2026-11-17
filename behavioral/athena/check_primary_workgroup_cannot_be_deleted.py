"""primary-workgroup-cannot-be-deleted."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "primary-workgroup-cannot-be-deleted"
GROUP = "managed-resource"
SERVICES = ["athena"]

_CANNOT_DELETE_PRIMARY = ("InvalidRequestException", "primary workGroup could not be deleted")


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The account's 'primary' workgroup exists without a caller create, and DeleteWorkGroup
    refuses to remove it while an identical delete on a caller-created workgroup succeeds."""
    athena = ctx.client("athena")

    primary = athena.get_work_group(WorkGroup="primary")["WorkGroup"]
    assert primary["Name"] == "primary", f"GetWorkGroup('primary') returned Name={primary['Name']!r}"
    assert primary["State"] == "ENABLED", f"expected primary to be ENABLED, got {primary['State']!r}"

    # Positive control: an ordinary, caller-created workgroup deletes cleanly.
    own_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=own_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    own_deleted = {"value": False}
    ctx.on_cleanup(
        lambda: own_deleted["value"] or athena.delete_work_group(WorkGroup=own_name)
    )
    athena.delete_work_group(WorkGroup=own_name)
    own_deleted["value"] = True
    own_gone = _error(lambda: athena.get_work_group(WorkGroup=own_name))
    assert own_gone == ("InvalidRequestException", "WorkGroup is not found."), (
        f"expected the deleted control workgroup to read back not-found, got {own_gone!r}"
    )

    # DeleteWorkGroup("primary") is refused with the specific, documented error.
    refusal = _error(lambda: athena.delete_work_group(WorkGroup="primary"))
    assert refusal == _CANNOT_DELETE_PRIMARY, f"expected {_CANNOT_DELETE_PRIMARY}, got {refusal!r}"

    # The refused delete had no effect: primary is still there and still usable.
    still_primary = athena.get_work_group(WorkGroup="primary")["WorkGroup"]
    assert still_primary["Name"] == "primary", (
        f"primary workgroup disappeared after a refused delete: {still_primary!r}"
    )
    assert still_primary["State"] == "ENABLED", (
        f"primary workgroup left ENABLED state after a refused delete: {still_primary['State']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
