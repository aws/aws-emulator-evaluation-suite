"""list-applications-max-results-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-applications-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListApplications rejects a maxResults value above the documented [1,50] range with ValidationException,
    while the boundary value of 50 is accepted."""
    emrs = ctx.client("emr-serverless")

    code, message = _error(lambda: emrs.list_applications(maxResults=51))
    assert code == "ValidationException", (
        f"expected ValidationException for maxResults=51, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 50"
    ), f"unexpected maxResults=51 message: {message!r}"

    # positive control: the maximum allowed value is accepted.
    resp = emrs.list_applications(maxResults=50)
    assert isinstance(resp["applications"], list), (
        f"expected 'applications' to be a list, got {type(resp.get('applications'))!r}"
    )
    assert len(resp["applications"]) <= 50, (
        f"expected at most 50 applications with maxResults=50, got {len(resp['applications'])}"
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
