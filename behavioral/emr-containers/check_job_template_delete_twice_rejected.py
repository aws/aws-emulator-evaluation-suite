"""job-template-delete-twice-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "job-template-delete-twice-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-containers"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a job template a second time is rejected with ValidationException
    (already deleted), while an equivalent delete on a different, still-existing
    template succeeds (positive control) in the same run."""
    emrc = ctx.client("emr-containers")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('emrc-exec-')}"
    job_template_data = {
        "executionRoleArn": role_arn,
        "releaseLabel": "emr-6.15.0-latest",
        "jobDriver": {
            "sparkSubmitJobDriver": {"entryPoint": "s3://sim2real-emrc-fixtures/a.py"}
        },
    }

    target = emrc.create_job_template(
        name=ctx.unique_name("sim2real-jt-"),
        clientToken=ctx.unique_name("tok-"),
        jobTemplateData=job_template_data,
    )
    control = emrc.create_job_template(
        name=ctx.unique_name("sim2real-jt-"),
        clientToken=ctx.unique_name("tok-"),
        jobTemplateData=job_template_data,
    )
    ctx.on_cleanup(lambda: _delete_ignore_not_found(emrc, target["id"]))
    ctx.on_cleanup(lambda: _delete_ignore_not_found(emrc, control["id"]))

    emrc.delete_job_template(id=target["id"])

    code, message = _client_error(lambda: emrc.delete_job_template(id=target["id"]))
    assert code == "ValidationException", (
        f"deleting an already-deleted job template returned {code!r}, expected "
        "'ValidationException'"
    )
    expected = "Template does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the template is still gone, not resurrected by the failed retry.
    not_found_code, not_found_message = _client_error(
        lambda: emrc.describe_job_template(id=target["id"])
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"describing the deleted target template returned {not_found_code!r}, expected "
        "'ResourceNotFoundException'"
    )
    expected = f"Job Template {target['id']} doesn't exist."
    assert not_found_message == expected, (
        f"expected message {expected!r}, got {not_found_message!r}"
    )

    # Positive control: deleting a different, still-live template succeeds.
    emrc.delete_job_template(id=control["id"])
    control_not_found, control_message = _client_error(
        lambda: emrc.describe_job_template(id=control["id"])
    )
    assert control_not_found == "ResourceNotFoundException", (
        f"describing the deleted control template returned {control_not_found!r}, expected "
        "'ResourceNotFoundException'"
    )
    expected = f"Job Template {control['id']} doesn't exist."
    assert control_message == expected, f"expected message {expected!r}, got {control_message!r}"


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
