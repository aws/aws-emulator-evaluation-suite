"""list-workflow-runs-reflects-status-transition."""
from __future__ import annotations

import re
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-workflow-runs-reflects-status-transition"
GROUP = "state"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWorkflowRuns reflects a run's status transition after UpdateWorkflowRun."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    wf_name = _wf_name(ctx, "wflst")
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

    def _find():
        resp = nova.list_workflow_runs(workflowDefinitionName=wf_name)
        for summary in resp["workflowRunSummaries"]:
            if summary["workflowRunId"] == run_id:
                return summary
        return None

    initial = _find()
    assert initial is not None, f"expected run {run_id} in ListWorkflowRuns({wf_name}), found none"
    assert initial["status"] == "RUNNING", f"expected initial status RUNNING, got {initial['status']!r}"
    assert initial.get("endedAt") is None, (
        f"expected no endedAt on a RUNNING summary, got {initial.get('endedAt')!r}"
    )

    nova.update_workflow_run(workflowDefinitionName=wf_name, workflowRunId=run_id, status="FAILED")

    final = _poll_until(_find, lambda s: s is not None and s["status"] == "FAILED", timeout_s=60.0, interval_s=2.0)
    # _poll_until's own predicate already pins status == "FAILED"; the real proof that
    # ListWorkflowRuns reflects the transition (not just the terminal status word) is that
    # the summary now carries an endedAt consistent with the run's startedAt.
    assert final.get("endedAt") is not None, (
        f"expected ListWorkflowRuns to populate endedAt once FAILED, got {final.get('endedAt')!r}"
    )
    assert final["endedAt"] >= initial["startedAt"], (
        f"expected endedAt {final['endedAt']!r} >= startedAt {initial['startedAt']!r}"
    )


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
