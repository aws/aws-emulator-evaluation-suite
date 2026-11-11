"""verify-procurement-portal-validation-wrong-code-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "verify-procurement-portal-validation-wrong-code-rejected"
GROUP = "overly-permissive"
SERVICES = ["invoicing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SendProcurementPortalValidation and VerifyProcurementPortalValidation on a
    nonexistent preference ARN both fail with ResourceNotFoundException and the same
    exact message."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = f"arn:aws:invoicing::{account_id}:procurement-portal-preference/sim2real-does-not-exist"

    expected_message = f"Procurement portal preference with arn {fake_arn} does not exist"

    send_err = _client_error(
        lambda: invoicing.send_procurement_portal_validation(ProcurementPortalPreferenceArn=fake_arn)
    )
    assert send_err["Code"] == "ResourceNotFoundException", (
        f"SendProcurementPortalValidation on a non-existent preference ARN should be rejected "
        f"with ResourceNotFoundException, got {send_err['Code']!r}"
    )
    assert send_err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {send_err['Message']!r}"
    )

    verify_err = _client_error(
        lambda: invoicing.verify_procurement_portal_validation(
            ProcurementPortalPreferenceArn=fake_arn, Code="000000"
        )
    )
    assert verify_err["Code"] == "ResourceNotFoundException", (
        f"VerifyProcurementPortalValidation on a non-existent preference ARN should be rejected "
        f"with ResourceNotFoundException, got {verify_err['Code']!r}"
    )
    assert verify_err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {verify_err['Message']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

