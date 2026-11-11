"""job-template-client-token-reuse-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "job-template-client-token-reuse-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-containers"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a clientToken from a previous CreateJobTemplate call with DIFFERENT
    request parameters is rejected with ValidationException, the original template is
    left untouched, and a fresh create (new token) still succeeds (positive control)."""
    emrc = ctx.client("emr-containers")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('emrc-exec-')}"
    name = ctx.unique_name("sim2real-jt-")
    token = ctx.unique_name("tok-")
    original_data = {
        "executionRoleArn": role_arn,
        "releaseLabel": "emr-6.15.0-latest",
        "jobDriver": {
            "sparkSubmitJobDriver": {"entryPoint": "s3://sim2real-emrc-fixtures/a.py"}
        },
    }

    original = emrc.create_job_template(
        name=name, clientToken=token, jobTemplateData=original_data
    )
    ctx.on_cleanup(lambda: _delete_ignore_not_found(emrc, original["id"]))

    conflicting_data = {
        "executionRoleArn": role_arn,
        "releaseLabel": "emr-6.15.0-latest",
        "jobDriver": {
            "sparkSubmitJobDriver": {"entryPoint": "s3://sim2real-emrc-fixtures/b.py"}
        },
    }
    code, message = _client_error(
        lambda: emrc.create_job_template(
            name=name, clientToken=token, jobTemplateData=conflicting_data
        )
    )
    assert code == "ValidationException", (
        f"reusing clientToken {token!r} with different jobTemplateData should be rejected "
        f"with ValidationException, got {code!r}"
    )
    expected = (
        "At least one input parameter differs from a previous call using the same client token"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the original template still has its original entryPoint.
    described = emrc.describe_job_template(id=original["id"])["jobTemplate"]
    entry = described["jobTemplateData"]["jobDriver"]["sparkSubmitJobDriver"]["entryPoint"]
    assert entry == "s3://sim2real-emrc-fixtures/a.py", (
        f"the original template's entryPoint changed to {entry!r} despite the conflicting "
        f"create being rejected"
    )

    # Positive control: create still works with a brand new clientToken.
    control = emrc.create_job_template(
        name=ctx.unique_name("sim2real-jt-"),
        clientToken=ctx.unique_name("tok-"),
        jobTemplateData=original_data,
    )
    ctx.on_cleanup(lambda: _delete_ignore_not_found(emrc, control["id"]))
    assert control["id"] != original["id"], (
        f"the control create returned the same id {control['id']!r} as the original template"
    )

    # Independent read at the destination: the control template is really persisted, not
    # just echoed back in the create response.
    control_described = emrc.describe_job_template(id=control["id"])["jobTemplate"]
    control_entry = control_described["jobTemplateData"]["jobDriver"]["sparkSubmitJobDriver"][
        "entryPoint"
    ]
    assert control_entry == "s3://sim2real-emrc-fixtures/a.py", (
        f"the control template describe returned entryPoint {control_entry!r}, expected the "
        f"data it was created with"
    )


def _delete_ignore_not_found(emrc, template_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        emrc.delete_job_template(id=template_id)
    except ClientError as err:
        # A job template already deleted in the run is refused with exactly this error.
        error = err.response["Error"]
        if (error["Code"], error.get("Message")) != (
            "ValidationException", "Template does not exist"
        ):
            raise


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so an
    accepted call that AWS refuses fails as accepted, not as an error mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
