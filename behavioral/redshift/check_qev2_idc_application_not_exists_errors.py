"""qev2-idc-application-not-exists-errors."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "qev2-idc-application-not-exists-errors"
GROUP = "error-semantics"
SERVICES = ["redshift"]

QEV2_NOT_EXISTS = "The Qev2IdcApplication you specified doesn't exist."
QEV2_NOT_EXISTS_OR_INCOMPLETE = (
    "The Qev2IdcApplication you specified doesn't exist or the status isn't Completed."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Describe/Modify/Delete on a nonexistent Query Editor V2 IDC application each raise
    Qev2IdcApplicationNotExists with its exact message, and nothing appears in the listing.

    Reference: https://docs.aws.amazon.com/redshift/latest/mgmt/redshift-iam-access-control-idp-connect-console.html
    """
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bogus_arn = (
        f"arn:aws:redshift:{ctx.region}:{account_id}:qev2idcapplication:"
        + ctx.unique_name("sim2real-behav-missing-")
    )

    # Positive control: an unfiltered list succeeds. The docs call these APIs unavailable in
    # the SDK, but the service model carries them and they answer without an IdC instance.
    listing = redshift.describe_qev2_idc_applications()
    assert "Qev2IdcApplications" in listing, (
        f"DescribeQev2IdcApplications (unfiltered): expected a Qev2IdcApplications key, got {listing!r}"
    )

    describe_code, describe_message = _error(
        lambda: redshift.describe_qev2_idc_applications(Qev2IdcApplicationArn=bogus_arn)
    )
    assert describe_code == "Qev2IdcApplicationNotExists", (
        f"DescribeQev2IdcApplications: expected Qev2IdcApplicationNotExists, got {describe_code}"
    )
    assert describe_message == QEV2_NOT_EXISTS, (
        f"DescribeQev2IdcApplications: expected message {QEV2_NOT_EXISTS!r}, got {describe_message!r}"
    )

    modify_code, modify_message = _error(
        lambda: redshift.modify_qev2_idc_application(
            Qev2IdcApplicationArn=bogus_arn, IdcDisplayName="sim2real-behav-missing"
        )
    )
    assert modify_code == "Qev2IdcApplicationNotExists", (
        f"ModifyQev2IdcApplication: expected Qev2IdcApplicationNotExists, got {modify_code}"
    )
    assert modify_message == QEV2_NOT_EXISTS_OR_INCOMPLETE, (
        f"ModifyQev2IdcApplication: expected message {QEV2_NOT_EXISTS_OR_INCOMPLETE!r}, "
        f"got {modify_message!r}"
    )

    delete_code, delete_message = _error(
        lambda: redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=bogus_arn)
    )
    assert delete_code == "Qev2IdcApplicationNotExists", (
        f"DeleteQev2IdcApplication: expected Qev2IdcApplicationNotExists, got {delete_code}"
    )
    assert delete_message == QEV2_NOT_EXISTS, (
        f"DeleteQev2IdcApplication: expected message {QEV2_NOT_EXISTS!r}, got {delete_message!r}"
    )

    # Effect absent: no rejected call registered an application under this ARN.
    remaining = redshift.describe_qev2_idc_applications().get("Qev2IdcApplications", [])
    assert all(app["Qev2IdcApplicationArn"] != bogus_arn for app in remaining), (
        "the nonexistent application must not appear in the account's application list "
        "after the rejected Describe/Modify/Delete calls"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
