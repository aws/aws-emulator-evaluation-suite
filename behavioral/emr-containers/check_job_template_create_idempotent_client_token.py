"""job-template-create-idempotent-client-token."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "job-template-create-idempotent-client-token"
GROUP = "state"
SERVICES = ["emr-containers"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateJobTemplate called twice with the SAME clientToken and identical params is
    idempotent: both calls resolve to the same job template id/arn, and only one
    template is actually persisted."""
    emrc = ctx.client("emr-containers")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('emrc-exec-')}"
    name = ctx.unique_name("sim2real-jt-")
    token = ctx.unique_name("tok-")
    job_template_data = {
        "executionRoleArn": role_arn,
        "releaseLabel": "emr-6.15.0-latest",
        "jobDriver": {
            "sparkSubmitJobDriver": {
                "entryPoint": "s3://sim2real-emrc-fixtures/scripts/main.py",
            }
        },
    }

    first = emrc.create_job_template(
        name=name, clientToken=token, jobTemplateData=job_template_data
    )
    ctx.on_cleanup(lambda: _delete_ignore_not_found(emrc, first["id"]))

    second = emrc.create_job_template(
        name=name, clientToken=token, jobTemplateData=job_template_data
    )

    assert second["id"] == first["id"], (
        f"second call with same clientToken should return the same id, "
        f"got first={first['id']!r} second={second['id']!r}"
    )
    assert second["arn"] == first["arn"], (
        f"second call with same clientToken should return the same arn, "
        f"got first={first['arn']!r} second={second['arn']!r}"
    )

    # No fan-out: exactly one template with this name is actually persisted,
    # proven on an independent side-channel (list) rather than by re-describing
    # the id the create calls already agreed on.
    matches = [t for t in _list_all(emrc) if t["name"] == name]
    assert len(matches) == 1, (
        f"expected exactly one persisted template named {name!r}, "
        f"got {len(matches)}: {matches}"
    )

    described = emrc.describe_job_template(id=first["id"])["jobTemplate"]
    assert described["name"] == name, (
        f"describe on the shared id should return name={name!r}, got {described['name']!r}"
    )


def _list_all(emrc):
    out = []
    next_token = None
    for _ in range(50):
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        page = emrc.list_job_templates(**kwargs)
        out.extend(page.get("templates", []))
        next_token = page.get("nextToken")
        if not next_token:
            break
    return out


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
