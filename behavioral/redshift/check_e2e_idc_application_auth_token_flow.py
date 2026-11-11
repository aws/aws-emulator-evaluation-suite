"""e2e-idc-application-auth-token-flow."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "e2e-idc-application-auth-token-flow"
GROUP = "e2e"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With plain IAM credentials GetIdentityCenterAuthToken is UnsupportedOperation;
    CreateRedshiftIdcApplication on an inaccessible IdC instance is DependentServiceAccessDenied;
    DeleteRedshiftIdcApplication on an absent ARN is RedshiftIdcApplicationNotExists.
    """
    redshift = ctx.client("redshift")

    # Positive control: plain IAM credentials work for an ordinary call, so each rejection below
    # is specific to its precondition.
    redshift.describe_clusters(MaxRecords=20)

    # GetIdentityCenterAuthToken works only with IAM Identity Center enhanced credentials.
    code_token, message_token = _error(
        lambda: redshift.get_identity_center_auth_token(ClusterIds=["sim2real-placeholder-cluster"])
    )
    assert code_token == "UnsupportedOperation", (
        f"expected a non-enhanced-credential caller to be rejected, got {code_token!r}"
    )
    assert message_token == "Request rejected: Not an IDC user acting", (
        f"unexpected GetIdentityCenterAuthToken message {message_token!r}"
    )

    fake_instance_arn = "arn:aws:sso:::instance/ssoins-0000000000000000"
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()
    account_id = caller["Account"]
    fake_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-idc-role"
    app_name = ctx.unique_name("sim2realidc").lower().replace("-", "")[:60]
    code_create, message_create = _error(
        lambda: redshift.create_redshift_idc_application(
            IdcInstanceArn=fake_instance_arn,
            RedshiftIdcApplicationName=app_name,
            IdcDisplayName="sim2real-behavioral-check",
            IamRoleArn=fake_role_arn,
        )
    )
    # Redshift's own call into IAM Identity Center for the fabricated instance is denied before
    # any application is registered.
    assert code_create == "DependentServiceAccessDenied", (
        f"expected a fabricated IdC instance ARN to be rejected with DependentServiceAccessDenied, got {code_create!r}"
    )
    # The relayed denial names the caller's own principal, so the expected text is built from the
    # caller's identity, and its per-request id suffix is removed before the exact comparison.
    expected_create = (
        f"User: {caller['Arn']} is not authorized to perform: sso:CreateApplication on resource: "
        "arn:aws:sso::*:application/ssoins-0000000000000000/* because no resource-based policy "
        "allows the sso:CreateApplication action"
    )
    assert message_create == expected_create, (
        f"expected message {expected_create!r}, got {message_create!r}"
    )
    apps = redshift.describe_redshift_idc_applications().get("RedshiftIdcApplications", [])
    assert not any(a.get("RedshiftIdcApplicationName") == app_name for a in apps), (
        f"rejected CreateRedshiftIdcApplication call nonetheless registered {app_name!r}"
    )


    fake_app_arn = (
        f"arn:aws:redshift:{ctx.region}:{account_id}:redshiftidcapplication:"
        "00000000-0000-0000-0000-000000000000"
    )
    code_delete, message_delete = _error(
        lambda: redshift.delete_redshift_idc_application(RedshiftIdcApplicationArn=fake_app_arn)
    )
    assert code_delete == "RedshiftIdcApplicationNotExists", (
        f"expected delete of a nonexistent application to be rejected, got {code_delete!r}"
    )
    expected_delete = f"The RedshiftIdcApplication with the ARN {fake_app_arn} wasn't found."
    assert message_delete == expected_delete, (
        f"expected message {expected_delete!r}, got {message_delete!r}"
    )

    # Positive control: a successful list does not contain the never-created application.
    apps = redshift.describe_redshift_idc_applications().get("RedshiftIdcApplications", [])
    assert not any(a.get("RedshiftIdcApplicationArn") == fake_app_arn for a in apps), (
        f"deleted (never-created) application {fake_app_arn!r} unexpectedly present in a live list"
    )



def _error(fn):
    """Call fn(); return (error code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], _without_request_suffix(err.response["Error"].get("Message"))
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


_REQUEST_SUFFIX = re.compile(
    r" \(Service: [A-Za-z0-9]+, Status Code: \d+, Request ID: [0-9a-fA-F-]+\)"
    r"( \(SDK Attempt Count: \d+\))?$"
)


def _without_request_suffix(message: str) -> str:
    """The message minus its per-request "(Service: ..., Request ID: ...) (SDK Attempt Count: n)"
    suffix, which is the only part that differs between calls."""
    return _REQUEST_SUFFIX.sub("", message or "")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
