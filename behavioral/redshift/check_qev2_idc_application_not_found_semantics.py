"""qev2-idc-application-not-found-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "qev2-idc-application-not-found-semantics"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Describe, Modify and Delete of a well-formed but never-created RedshiftIdcApplication ARN each
    answer RedshiftIdcApplicationNotExists with the same exact message, and the unfiltered describe
    lists no such application."""
    redshift = ctx.client("redshift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:redshift:{ctx.region}:{account_id}:redshiftidcapplication:"
        f"{ctx.unique_name('sim2real-nope-')}"
    )
    not_exists = f"The RedshiftIdcApplication with the ARN {bogus_arn} wasn't found."

    describe_code, describe_message = _error(
        lambda: redshift.describe_redshift_idc_applications(RedshiftIdcApplicationArn=bogus_arn)
    )
    assert describe_code == "RedshiftIdcApplicationNotExists", (
        f"DescribeRedshiftIdcApplications: expected RedshiftIdcApplicationNotExists, got {describe_code!r}"
    )
    assert describe_message == not_exists, (
        f"DescribeRedshiftIdcApplications: expected message {not_exists!r}, got {describe_message!r}"
    )

    modify_code, modify_message = _error(
        lambda: redshift.modify_redshift_idc_application(
            RedshiftIdcApplicationArn=bogus_arn, IdcDisplayName="whatever"
        )
    )
    assert modify_code == "RedshiftIdcApplicationNotExists", (
        f"ModifyRedshiftIdcApplication: expected RedshiftIdcApplicationNotExists, got {modify_code!r}"
    )
    assert modify_message == not_exists, (
        f"ModifyRedshiftIdcApplication: expected message {not_exists!r}, got {modify_message!r}"
    )

    delete_code, delete_message = _error(
        lambda: redshift.delete_redshift_idc_application(RedshiftIdcApplicationArn=bogus_arn)
    )
    assert delete_code == "RedshiftIdcApplicationNotExists", (
        f"DeleteRedshiftIdcApplication: expected RedshiftIdcApplicationNotExists, got {delete_code!r}"
    )
    assert delete_message == not_exists, (
        f"DeleteRedshiftIdcApplication: expected message {not_exists!r}, got {delete_message!r}"
    )

    # Positive control + independent terminal read: an unfiltered list call succeeds (the API
    # itself is not universally broken) and never carries the bogus ARN, since none of the three
    # rejected calls above could have created, renamed or removed anything.
    listing = redshift.describe_redshift_idc_applications()
    assert "RedshiftIdcApplications" in listing, (
        f"DescribeRedshiftIdcApplications (unfiltered): expected the normal list shape, got {listing!r}"
    )
    assert all(
        app["RedshiftIdcApplicationArn"] != bogus_arn
        for app in listing["RedshiftIdcApplications"]
    ), "the nonexistent application must not appear in the account's application list"


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
