"""op-contract-set-security-token-service-preferences."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-set-security-token-service-preferences"
GROUP = "error-semantics"
SERVICES = ["iam"]


def _unvalidated_client(ctx):
    """An IAM client with botocore's client-side parameter validation disabled.

    GlobalEndpointTokenVersion is a modeled enum (v1Token/v2Token), but botocore does not enforce
    enum membership client-side -- there is no local ParamValidationError to catch here, so the
    ordinary client already reaches the service. Routing through the unvalidated client anyway
    removes any doubt (a ParamValidationError caught as "the rejection" would prove nothing
    about the target, since the request never left the SDK). iam is this check's own service, so the pinned endpoint is the right one
    both on real AWS and against an emulator.
    """
    return ctx.client(
        "iam", config=Config(retries={"max_attempts": 1}, parameter_validation=False)
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:sts-token-preferences")
def run(ctx) -> None:
    """SetSecurityTokenServicePreferences flips GlobalEndpointTokenVersion, observable via GetAccountSummary."""
    iam = ctx.client("iam")

    summary = iam.get_account_summary()["SummaryMap"]
    current = summary.get("GlobalEndpointTokenVersion", 1)
    new_str, new_num = ("v1Token", 1) if current == 2 else ("v2Token", 2)
    original_str = "v1Token" if current == 1 else "v2Token"

    ctx.on_cleanup(lambda: iam.set_security_token_service_preferences(GlobalEndpointTokenVersion=original_str))

    iam.set_security_token_service_preferences(GlobalEndpointTokenVersion=new_str)

    def _probe():
        return iam.get_account_summary()["SummaryMap"].get("GlobalEndpointTokenVersion")

    observed = _poll_until(_probe, lambda v: v == new_num, timeout_s=30, interval_s=1.5)
    assert observed == new_num, f"GlobalEndpointTokenVersion did not converge to {new_num}, saw {observed}"

    # Error boundary: GlobalEndpointTokenVersion only accepts the two documented enum values.
    # Forced through the unvalidated client (see _unvalidated_client) so the rejection is the
    # service's, not the SDK's.
    raw = _unvalidated_client(ctx)
    try:
        raw.set_security_token_service_preferences(GlobalEndpointTokenVersion="not-a-real-token-version")
        raise AssertionError("expected a validation error for an invalid GlobalEndpointTokenVersion")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        msg = exc.response["Error"].get("Message") or ""
        assert code == "ValidationError", (
            "an invalid GlobalEndpointTokenVersion must be rejected with ValidationError, got "
            f"{code!r}: {msg!r}"
        )
        want = ("1 validation error detected: Value at 'globalEndpointTokenVersion' failed to "
                "satisfy constraint: Member must satisfy enum value set: [v2Token, v1Token]")
        assert msg == want, f"ValidationError message: wanted {want!r}, got {msg!r}"

    unchanged = iam.get_account_summary()["SummaryMap"].get("GlobalEndpointTokenVersion")
    assert unchanged == new_num, (
        "a rejected SetSecurityTokenServicePreferences must not change GlobalEndpointTokenVersion; "
        f"expected it to remain {new_num}, got {unchanged!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise AssertionError(f"condition not met within {timeout_s}s; last observation {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
