"""application-provider-not-found-describe-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-provider-not-found-describe-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-admin"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeApplicationProvider against a syntactically well-formed but nonexistent/not-a-
    built-in ApplicationProviderArn is rejected with ResourceNotFoundException, while a real
    built-in provider ARN from ListApplicationProviders still describes cleanly."""
    sso = ctx.client("sso-admin")

    bogus_arn = "arn:aws:sso::aws:applicationProvider/sim2real-behav-not-a-real-provider"
    code, message = _error(lambda: sso.describe_application_provider(ApplicationProviderArn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"No application provider with arn '{bogus_arn}' was found", message

    # Positive control: a real built-in provider ARN still describes cleanly.
    real_arn = "arn:aws:sso::aws:applicationProvider/custom"
    described = sso.describe_application_provider(ApplicationProviderArn=real_arn)
    assert described["ApplicationProviderArn"] == real_arn, (
        f"expected ApplicationProviderArn {real_arn!r}, got {described.get('ApplicationProviderArn')!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts a call AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

