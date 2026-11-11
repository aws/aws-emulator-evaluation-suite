"""list-applications-maxresults-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "list-applications-maxresults-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListApplications with maxResults 0 or 51, sent past client-side validation, fails with ValidationException
    and the exact message, while maxResults 1 and 50 list applications."""
    emrs = ctx.client("emr-serverless")

    # Positive control: both ends of the documented range are accepted.
    resp_low = emrs.list_applications(maxResults=1)
    assert "applications" in resp_low, (
        f"expected 'applications' in response, got keys {list(resp_low)}"
    )
    resp_high = emrs.list_applications(maxResults=50)
    assert "applications" in resp_high, (
        f"expected 'applications' in response, got keys {list(resp_high)}"
    )

    raw = ctx.client("emr-serverless", config=Config(parameter_validation=False))

    # Break exactly one thing: maxResults below the documented minimum.
    code_zero, message_zero = _error(lambda: raw.list_applications(maxResults=0))
    assert code_zero == "ValidationException", (
        f"expected ValidationException for maxResults=0, got {code_zero!r}"
    )
    assert message_zero == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: Member must have value greater than or equal to 1"
    ), f"unexpected maxResults=0 message: {message_zero!r}"

    # Break exactly one thing: maxResults above the documented ceiling.
    code_over, message_over = _error(lambda: raw.list_applications(maxResults=51))
    assert code_over == "ValidationException", (
        f"expected ValidationException for maxResults=51, got {code_over!r}"
    )
    assert message_over == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 50"
    ), f"unexpected maxResults=51 message: {message_over!r}"

    # The identical raw (unvalidated) client still accepts an in-range call.
    control_raw = raw.list_applications(maxResults=50)
    assert "applications" in control_raw, (
        f"expected 'applications' in raw-client response, got keys {list(control_raw)}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
