"""create-redshift-idc-application-dependent-service-rejected."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "create-redshift-idc-application-dependent-service-rejected"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRedshiftIdcApplication with a well-formed but nonexistent IAM Identity Center instance ARN
    is rejected with DependentServiceAccessDenied and its exact message, and
    DescribeRedshiftIdcApplications lists no such application."""
    redshift = ctx.client("redshift")
    caller = ctx.client("sts").get_caller_identity()
    account_id = caller["Account"]

    app_name = ctx.unique_name("sim2real-idcapp-")
    import hashlib

    suffix = hashlib.sha1(app_name.encode()).hexdigest()[:16]
    bogus_idc_instance_arn = f"arn:aws:sso:::instance/ssoins-{suffix}"
    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-idcrole-')}"

    code, message = _error_code(
        lambda: redshift.create_redshift_idc_application(
            IdcInstanceArn=bogus_idc_instance_arn,
            RedshiftIdcApplicationName=app_name,
            IdcDisplayName="Sim2Real-Test-IdC-App",
            IamRoleArn=bogus_role_arn,
        )
    )
    assert code == "DependentServiceAccessDenied", code
    # AWS relays the IAM Identity Center denial verbatim: it names the caller's own principal,
    # so the expected text is built from the caller's identity, and its per-request id suffix is
    # removed before the exact comparison.
    expected = (
        f"User: {caller['Arn']} is not authorized to perform: sso:CreateApplication on resource: "
        f"arn:aws:sso::*:application/ssoins-{suffix}/* because no resource-based policy allows "
        "the sso:CreateApplication action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no application under this name was actually created.
    described = redshift.describe_redshift_idc_applications()["RedshiftIdcApplications"]
    names = {a["RedshiftIdcApplicationName"] for a in described}
    assert app_name not in names, f"expected {app_name!r} absent, found in {names!r}"

    # positive control: read-only describe (no live IdC instance required) still succeeds.
    redshift.describe_redshift_idc_applications()


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        code = err.response["Error"]["Code"]
        msg = err.response["Error"].get("Message", "")
        if code == "ValidationError":
            raise AssertionError(f"ValidationError message: {msg}") from None
        return code, _without_request_suffix(msg)
    raise AssertionError("expected a ClientError, but the call succeeded")


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
