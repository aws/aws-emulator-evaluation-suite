"""list-job-templates-pagination."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "list-job-templates-pagination"
GROUP = "data-plane"
SERVICES = ["emr-containers"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListJobTemplates with maxResults=1 returns exactly one item per page and, when
    the returned nextToken is followed to exhaustion, every created template shows up
    exactly once across the pages (no drops, no duplicates)."""
    emrc = ctx.client("emr-containers")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('emrc-exec-')}"
    created_after = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)
    job_template_data = {
        "executionRoleArn": role_arn,
        "releaseLabel": "emr-6.15.0-latest",
        "jobDriver": {
            "sparkSubmitJobDriver": {"entryPoint": "s3://sim2real-emrc-fixtures/a.py"}
        },
    }

    created_ids = []
    for _ in range(3):
        resp = emrc.create_job_template(
            name=ctx.unique_name("sim2real-jt-"),
            clientToken=ctx.unique_name("tok-"),
            jobTemplateData=job_template_data,
            tags={"sim2real": "true"},
        )
        created_ids.append(resp["id"])
        ctx.on_cleanup(lambda tid=resp["id"]: _delete_ignore_not_found(emrc, tid))

    seen_ids = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"maxResults": 1, "createdAfter": created_after}
        if next_token:
            kwargs["nextToken"] = next_token
        page = emrc.list_job_templates(**kwargs)
        page_templates = page.get("templates", [])
        assert len(page_templates) <= 1, (
            f"maxResults=1 but page {pages} returned {len(page_templates)} templates"
        )
        seen_ids.extend(t["id"] for t in page_templates)
        next_token = page.get("nextToken")
        pages += 1
        if not next_token or pages > 50:
            break

    for tid in created_ids:
        assert seen_ids.count(tid) == 1, f"template {tid} appeared {seen_ids.count(tid)} times"


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
