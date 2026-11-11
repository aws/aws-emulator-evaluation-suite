"""get-enrollment-statuses-for-organization-non-management-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-enrollment-statuses-for-organization-non-management-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetEnrollmentStatusesForOrganization from a non-management account fails with
    InvalidParameterValueException and its exact message, while GetEnrollmentStatus on the same client
    succeeds."""
    co = ctx.client("compute-optimizer")

    code, message = _error(lambda: co.get_enrollment_statuses_for_organization())
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    expected = (
        "You can't get enrollment statuses for member accounts of an organization. This "
        "might be because you aren't a user of an organization account, or you aren't "
        "the management account or delegated administrator of the organization."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: a basic account-scoped call on the same client still succeeds,
    # proving the rejection is specific to this operation/boundary, not a broken client.
    resp = co.get_enrollment_status()
    assert resp["status"] in ("Active", "Inactive", "Pending", "Failed"), (
        f"expected status to be one of Active/Inactive/Pending/Failed, got {resp.get('status')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call from a non-management account, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
