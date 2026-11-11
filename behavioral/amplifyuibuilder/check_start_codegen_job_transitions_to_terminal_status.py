"""start-codegen-job-transitions-to-terminal-status."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-codegen-job-transitions-to-terminal-status"
GROUP = "state-machine"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartCodegenJob creates a codegen job that begins in_progress and, polled via
    GetCodegenJob, eventually reaches a terminal status (succeeded or failed) instead of
    hanging in in_progress forever."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")

    started = uib.start_codegen_job(
        appId=app_id,
        environmentName=_ENV,
        codegenJobToCreate={
            "renderConfig": {
                "react": {
                    "module": "es2020",
                    "target": "es2020",
                    "script": "jsx",
                    "renderTypeDeclarations": False,
                    "inlineSourceMap": False,
                }
            },
            "autoGenerateForms": False,
        },
    )["entity"]
    job_id = started["id"]
    assert started["appId"] == app_id, f"expected appId {app_id!r}, got {started['appId']!r}"
    assert (
        started["environmentName"] == _ENV
    ), f"expected environmentName {_ENV!r}, got {started['environmentName']!r}"

    deadline = time.monotonic() + 180
    status = started.get("status", "in_progress")
    job = None
    while time.monotonic() < deadline:
        job = uib.get_codegen_job(appId=app_id, environmentName=_ENV, id=job_id)["job"]
        status = job["status"]
        if status != "in_progress":
            break
        time.sleep(5)

    assert status in ("succeeded", "failed"), f"codegen job never reached a terminal status: {status}"
    assert job is not None and job["id"] == job_id, f"expected job id {job_id!r}, got {job and job.get('id')!r}"


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    import random

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name)
            app_id = resp["app"]["appId"]
            ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
            return app_id
        except ClientError as e:
            if "Rate exceeded" in str(e) and attempt < 19:
                time.sleep(min(30, 2**attempt) + random.uniform(0, 10))
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
