"""list-enrollment-statuses-account-id-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-enrollment-statuses-account-id-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["cost-optimization-hub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEnrollmentStatuses rejects an accountId that fails the ^[0-9]{12}$ pattern,
    while a syntactically valid accountId in the same call shape still succeeds."""
    # cost-optimization-hub is a control-plane service that only exists in us-east-1.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # Positive control first, same call shape as the negative below: filtering by the caller's
    # OWN account id is permitted for any member account (only filtering by an ARBITRARY other
    # account id needs the organization's management-account entitlement, which this check does
    # not exercise), so it succeeds without requiring any special account setup.
    own_account = ctx.client("sts").get_caller_identity()["Account"]
    control = coh.list_enrollment_statuses(accountId=own_account)
    assert isinstance(control["items"], list), (
        f"the positive control (accountId={own_account!r}, the caller's own account) did not "
        f"return a list of items: {control!r}"
    )

    error = _client_error(lambda: coh.list_enrollment_statuses(accountId="not-an-account-id"))
    assert error.get("Code") == "ValidationException", (
        f"an accountId failing the ^[0-9]{{12}}$ pattern was rejected with "
        f"{error.get('Code')!r}, expected 'ValidationException'"
    )
    assert error.get("Message") == (
        "Input validation failed. Please check the field list for more details."
    ), (
        f"the validation rejection message was {error.get('Message')!r}, expected "
        f"'Input validation failed. Please check the field list for more details.'"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects an accountId failing ^[0-9]{{12}}$, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
