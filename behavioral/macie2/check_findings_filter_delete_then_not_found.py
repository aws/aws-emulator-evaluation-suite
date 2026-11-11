"""findings-filter-delete-then-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "findings-filter-delete-then-not-found"
GROUP = "state"
SERVICES = ["macie2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """Delete is a genuine hard delete: an independent GetFindingsFilter reports
    ResourceNotFoundException afterward, and a further mutation (UpdateFindingsFilter)
    against the same dead id is rejected the same way rather than silently succeeding."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    name = ctx.unique_name("sim2real-macie-filt-")
    filter_id = macie.create_findings_filter(
        name=name,
        action="NOOP",
        findingCriteria={"criterion": {"sample": {"eq": ["true"]}}},
        clientToken=ctx.unique_name("sim2real-macie-filt-tok-"),
        tags={"sim2real": "true"},
    )["id"]
    ctx.on_cleanup(lambda: _delete_if_present(macie, filter_id))

    before = macie.get_findings_filter(id=filter_id)
    assert before["name"] == name, (
        f"expected the created filter (positive control) to be visible before delete "
        f"with name={name!r}, got {before!r}"
    )

    macie.delete_findings_filter(id=filter_id)

    code, message = _error_code(lambda: macie.get_findings_filter(id=filter_id))
    assert code == "ResourceNotFoundException", (
        f"expected GetFindingsFilter on a deleted filter to raise ResourceNotFoundException, "
        f"got {code!r}"
    )
    expected_message = "Resource not found. Verify any provided IDs are correct."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_code, update_message = _error_code(
        lambda: macie.update_findings_filter(id=filter_id, description="probe-after-delete")
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateFindingsFilter on a deleted filter to raise ResourceNotFoundException, "
        f"got {update_code!r}"
    )
    expected_update_message = "Resource not found. Verify any provided IDs are correct."
    assert update_message == expected_update_message, (
        f"expected message {expected_update_message!r}, got {update_message!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _delete_if_present(macie, filter_id) -> None:
    from botocore.exceptions import ClientError

    try:
        macie.delete_findings_filter(id=filter_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _ensure_macie_enabled(ctx) -> None:
    """Enable Macie when the account has no session, and disable it again at cleanup so the
    account-wide setting ends in the state it started in."""
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
        return
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
    try:
        macie.enable_macie()
    except ClientError as exc2:
        if exc2.response["Error"]["Code"] != "ConflictException":
            raise
        return
    ctx.on_cleanup(macie.disable_macie)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
