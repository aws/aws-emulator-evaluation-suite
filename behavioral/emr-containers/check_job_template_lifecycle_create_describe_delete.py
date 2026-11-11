"""job-template-lifecycle-create-describe-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "job-template-lifecycle-create-describe-delete"
GROUP = "state"
SERVICES = ["emr-containers"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateJobTemplate persists jobTemplateData verbatim; after DeleteJobTemplate the
    template is gone (ResourceNotFoundException on describe)."""
    emrc = ctx.client("emr-containers")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('emrc-exec-')}"
    name = ctx.unique_name("sim2real-jt-")
    job_template_data = {
        "executionRoleArn": role_arn,
        "releaseLabel": "emr-6.15.0-latest",
        "jobDriver": {
            "sparkSubmitJobDriver": {
                "entryPoint": "s3://sim2real-emrc-fixtures/scripts/main.py",
                "sparkSubmitParameters": "--conf spark.executor.instances=2",
            }
        },
    }

    created = emrc.create_job_template(
        name=name,
        clientToken=ctx.unique_name("tok-"),
        jobTemplateData=job_template_data,
        tags={"sim2real-check": CHECK},
    )
    template_id = created["id"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(emrc, template_id))

    described = emrc.describe_job_template(id=template_id)["jobTemplate"]
    assert described["name"] == name, (
        f"expected describe_job_template name {name!r}, got {described['name']!r}"
    )
    data = described["jobTemplateData"]
    assert data["executionRoleArn"] == role_arn, (
        f"expected executionRoleArn {role_arn!r}, got {data['executionRoleArn']!r}"
    )
    assert data["releaseLabel"] == "emr-6.15.0-latest", (
        f"expected releaseLabel 'emr-6.15.0-latest', got {data['releaseLabel']!r}"
    )
    assert data["jobDriver"]["sparkSubmitJobDriver"]["entryPoint"] == (
        "s3://sim2real-emrc-fixtures/scripts/main.py"
    ), (
        "expected entryPoint 's3://sim2real-emrc-fixtures/scripts/main.py', got "
        f"{data['jobDriver']['sparkSubmitJobDriver']['entryPoint']!r}"
    )
    assert data["jobDriver"]["sparkSubmitJobDriver"]["sparkSubmitParameters"] == (
        "--conf spark.executor.instances=2"
    ), (
        "expected sparkSubmitParameters '--conf spark.executor.instances=2', got "
        f"{data['jobDriver']['sparkSubmitJobDriver']['sparkSubmitParameters']!r}"
    )

    emrc.delete_job_template(id=template_id)

    code, message = _client_error(lambda: emrc.describe_job_template(id=template_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on describe after delete, got {code!r}"
    )
    expected = f"Job Template {template_id} doesn't exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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
