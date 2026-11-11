"""op-contract-enableReachabilityAnalyzerOrganizationSharing."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-enableReachabilityAnalyzerOrganizationSharing"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableReachabilityAnalyzerOrganizationSharing with DryRun answers DryRunOperation; from an account
    that is not the management account the real call fails with
    NetworkInsightsMultiAccount.AccessDenied (exact messages)."""
    ec2 = ctx.client("ec2")

    dry_run_code, dry_run_message = _client_error(
        lambda: ec2.enable_reachability_analyzer_organization_sharing(DryRun=True)
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code}"
    expected_dry = "Request would have succeeded, but DryRun flag is set."
    assert dry_run_message == expected_dry, f"expected message {expected_dry!r}, got {dry_run_message!r}"

    real_error = None
    real_message = None
    real_value = None
    try:
        real_value = ec2.enable_reachability_analyzer_organization_sharing()
    except Exception as exc:  # noqa: BLE001 - we branch explicitly below
        from botocore.exceptions import ClientError

        if isinstance(exc, ClientError):
            real_error = exc.response["Error"]["Code"]
            real_message = exc.response["Error"].get("Message")
        else:
            raise

    if real_error is not None:
        # The specific per-account entitlement gate: a non-management-account caller gets
        # this exact code, not a generic AccessDenied/UnauthorizedOperation, and the message
        # names the management-account requirement rather than a bare permission refusal.
        assert real_error == "NetworkInsightsMultiAccount.AccessDenied", (
            "expected the management-account entitlement gate "
            f"NetworkInsightsMultiAccount.AccessDenied, got {real_error!r} (message={real_message!r})"
        )
        expected_denied = (
            "The caller is not authorized to call organizations:EnableAWSServiceAccess due to not "
            "being a management account"
        )
        assert real_message == expected_denied, (
            f"expected message {expected_denied!r}, got {real_message!r}"
        )
    else:
        # Unexpected but valid on an actual Organizations management account: the call
        # really enabled sharing, so assert the success contract and clean up.
        assert real_value["ReturnValue"] is True, (
            f"expected ReturnValue=True from a management-account caller, got {real_value!r}"
        )
        ctx.on_cleanup(lambda: ec2.disable_reachability_analyzer_organization_sharing())


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
