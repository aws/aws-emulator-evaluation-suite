"""workflow-run-update-to-succeeded-sets-ended-at."""
from __future__ import annotations

import re
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "workflow-run-update-to-succeeded-sets-ended-at"
GROUP = "state"
SERVICES = ["nova-act"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWorkflowRun(status=SUCCEEDED) drives RUNNING->SUCCEEDED and populates endedAt."""
    nova = _nova_client(ctx)
    wf_name = _wf_name(ctx, "wfrun")
    nova.create_workflow_definition(name=wf_name, clientToken=_client_token())
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=wf_name)))

    model_id, version = _pick_model(nova)
    run_id = nova.create_workflow_run(
        workflowDefinitionName=wf_name,
        modelId=model_id,
        clientToken=_client_token(),
        clientInfo={"compatibilityVersion": version, "sdkVersion": "sim2real-behavioral-1.0"},
    )["workflowRunId"]
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_run(workflowDefinitionName=wf_name, workflowRunId=run_id)))

    before = nova.get_workflow_run(workflowDefinitionName=wf_name, workflowRunId=run_id)
    assert before["status"] == "RUNNING", f"expected freshly-created run status RUNNING, got {before['status']!r}"
    assert "endedAt" not in before, f"expected no endedAt on a RUNNING run, got {before.get('endedAt')!r}"

    nova.update_workflow_run(workflowDefinitionName=wf_name, workflowRunId=run_id, status="SUCCEEDED")

    def _probe():
        return nova.get_workflow_run(workflowDefinitionName=wf_name, workflowRunId=run_id)

    final = _poll_until(_probe, lambda r: r["status"] == "SUCCEEDED", timeout_s=60.0, interval_s=2.0)
    assert final["status"] == "SUCCEEDED", f"expected status SUCCEEDED after update, got {final['status']!r}"
    assert "endedAt" in final and final["endedAt"] is not None, (
        f"expected UpdateWorkflowRun(SUCCEEDED) to populate endedAt, got {final.get('endedAt')!r}"
    )
    assert final["endedAt"] >= final["startedAt"], (
        f"expected endedAt >= startedAt, got endedAt={final['endedAt']!r} startedAt={final['startedAt']!r}"
    )


def _nova_client(ctx):
    """Nova Act's control plane is served only in us-east-1, whatever the harness's default
    region; pin the region on the harness client so every target gets the same request."""
    return ctx.client("nova-act", region="us-east-1")  # region-pinned: control plane is us-east-1 only


def _wf_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"n{kind}")
    return re.sub(r"[^a-zA-Z0-9_-]", "-", raw)[:40]


def _client_token() -> str:
    return uuid.uuid4().hex + "-" + uuid.uuid4().hex


def _pick_model(nova):
    for version in (1, 2, 3, 5, 8, 13, 21):
        resp = nova.list_models(clientCompatibilityVersion=version)
        aliases = resp.get("modelAliases") or []
        ga_aliases = [a["aliasName"] for a in aliases if a.get("aliasName") and "preview" not in a["aliasName"]]
        if ga_aliases:
            return ga_aliases[0], version
        if aliases:
            return aliases[0]["aliasName"], version
    # "nova-act-latest" is a documented, always-available GA alias; CreateWorkflowRun
    # rejects a raw preview modelId directly, so prefer an alias over modelSummaries.
    return "nova-act-latest", 1


def _silent(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
