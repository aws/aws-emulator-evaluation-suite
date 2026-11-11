"""qev2-idc-application-delete-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "qev2-idc-application-delete-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["redshift"]

_NOT_EXISTS_MESSAGE = "The Qev2IdcApplication you specified doesn't exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQev2IdcApplication and DescribeQev2IdcApplications on an ARN that was
    never created return the Qev2-specific Qev2IdcApplicationNotExists, not a
    generic not-found shape."""
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:redshift:{ctx.region}:{account_id}:qev2idcapplication:"
        + ctx.unique_name("sim2real-qev2-ghost-")
    )

    delete_code, delete_message = _error(
        lambda: redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=bogus_arn)
    )
    assert delete_code == "Qev2IdcApplicationNotExists", (
        f"expected Qev2IdcApplicationNotExists, got {delete_code!r}"
    )
    assert delete_message == _NOT_EXISTS_MESSAGE, (
        f"unexpected Qev2IdcApplicationNotExists message {delete_message!r}"
    )

    describe_code, describe_message = _error(
        lambda: redshift.describe_qev2_idc_applications(Qev2IdcApplicationArn=bogus_arn)
    )
    assert describe_code == "Qev2IdcApplicationNotExists", (
        f"expected Qev2IdcApplicationNotExists, got {describe_code!r}"
    )
    assert describe_message == _NOT_EXISTS_MESSAGE, (
        f"unexpected Qev2IdcApplicationNotExists message {describe_message!r}"
    )

    # Positive control: describing without a specific ARN filter (a normal list
    # call) succeeds rather than the API being universally broken.
    listing = redshift.describe_qev2_idc_applications()
    assert "Qev2IdcApplications" in listing


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
