"""job-template-tags-round-trip."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "job-template-tags-round-trip"
GROUP = "data-plane"
SERVICES = ["emr-containers"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied to CreateJobTemplate are persisted verbatim and returned exactly
    by both DescribeJobTemplate and ListJobTemplates (two independent reads, neither
    the mutating call's own response)."""
    emrc = ctx.client("emr-containers")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('emrc-exec-')}"
    created_tags = {"Team": "data-eng", "Env": "sim2real"}
    created_after = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)

    created = emrc.create_job_template(
        name=ctx.unique_name("sim2real-jt-"),
        clientToken=ctx.unique_name("tok-"),
        jobTemplateData={
            "executionRoleArn": role_arn,
            "releaseLabel": "emr-6.15.0-latest",
            "jobDriver": {
                "sparkSubmitJobDriver": {"entryPoint": "s3://sim2real-emrc-fixtures/a.py"}
            },
        },
        tags=created_tags,
    )
    template_id = created["id"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(emrc, template_id))

    described = emrc.describe_job_template(id=template_id)["jobTemplate"]
    assert described.get("tags") == created_tags, (
        f"describe_job_template tags: expected {created_tags}, got {described.get('tags')}"
    )

    listed_entry = _find_in_list(emrc, template_id, created_after)
    assert listed_entry is not None, (
        f"template {template_id} did not appear in list_job_templates(createdAfter={created_after})"
    )
    assert listed_entry.get("tags") == created_tags, (
        f"list_job_templates tags: expected {created_tags}, got {listed_entry.get('tags')}"
    )


def _find_in_list(emrc, template_id: str, created_after):
    next_token = None
    for _ in range(200):
        kwargs = {"createdAfter": created_after}
        if next_token:
            kwargs["nextToken"] = next_token
        page = emrc.list_job_templates(**kwargs)
        for entry in page.get("templates", []):
            if entry["id"] == template_id:
                return entry
        next_token = page.get("nextToken")
        if not next_token:
            break
    return None


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
