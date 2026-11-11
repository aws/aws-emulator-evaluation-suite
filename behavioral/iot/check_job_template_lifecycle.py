"""job-template-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-template-lifecycle"
GROUP = 'job-lifecycle'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) if a ClientError is raised. An unexpected
    success raises, so a target that accepts the call cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")

def _delete_job_template(iot, template_id):
    """Best-effort teardown: delete a job template."""
    try:
        iot.delete_job_template(jobTemplateId=template_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateJobTemplate -> Describe -> List -> Delete, and a deleted template is both gone
    (an independent read 404s) and unusable (a mutation against the dead id also 404s)."""
    iot = ctx.client("iot")
    template_id = ctx.unique_name("sim2real-behav-jobtmpl-")
    iot.create_job_template(
        jobTemplateId=template_id,
        description="probe template",
        document=json.dumps({"operation": "reboot"}),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _t=template_id: _delete_job_template(iot, _t))

    desc = iot.describe_job_template(jobTemplateId=template_id)
    assert desc["jobTemplateId"] == template_id, f"expected {template_id}, got {desc['jobTemplateId']}"
    assert desc["description"] == "probe template", f"unexpected description: {desc['description']!r}"

    ids = [t["jobTemplateId"] for t in iot.list_job_templates().get("jobTemplates", [])]
    assert template_id in ids, f"{template_id} missing from ListJobTemplates"

    iot.delete_job_template(jobTemplateId=template_id)
    code, message = _err(lambda: iot.describe_job_template(jobTemplateId=template_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Job Template {template_id} cannot be found.", message

    # A mutation against the dead id must also fail, not just a read.
    redelete_code, redelete_message = _err(lambda: iot.delete_job_template(jobTemplateId=template_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"deleting an already-deleted job template: expected ResourceNotFoundException, got {redelete_code}"
    )
    assert redelete_message == f"Job Template {template_id} cannot be found.", redelete_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
