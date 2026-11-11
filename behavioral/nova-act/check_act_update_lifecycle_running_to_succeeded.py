"""act-update-lifecycle-running-to-succeeded."""
from __future__ import annotations

import re
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "act-update-lifecycle-running-to-succeeded"
GROUP = "state"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAct(status=SUCCEEDED) transitions a RUNNING act and is reflected via ListActs."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    wf_name = _wf_name(ctx, "wfau")
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

    session_id = nova.create_session(
        workflowDefinitionName=wf_name, workflowRunId=run_id, clientToken=_client_token()
    )["sessionId"]
    act_id = nova.create_act(
        workflowDefinitionName=wf_name,
        workflowRunId=run_id,
        sessionId=session_id,
        task="Do nothing and wait to be marked complete.",
        clientToken=_client_token(),
    )["actId"]

    nova.update_act(
        workflowDefinitionName=wf_name,
        workflowRunId=run_id,
        sessionId=session_id,
        actId=act_id,
        status="SUCCEEDED",
    )

    def _probe():
        resp = nova.list_acts(workflowDefinitionName=wf_name, workflowRunId=run_id, sessionId=session_id)
        for summary in resp["actSummaries"]:
            if summary["actId"] == act_id:
                return summary
        return None

    summary = _poll_until(_probe, lambda s: s is not None and s["status"] == "SUCCEEDED", timeout_s=60.0, interval_s=2.0)
    assert summary["status"] == "SUCCEEDED", f"expected status SUCCEEDED after UpdateAct, got {summary['status']!r}"
    ended_at = summary.get("endedAt")
    assert ended_at is not None, "expected endedAt to be populated once the act reached SUCCEEDED"
    started_at = summary.get("startedAt")
    assert started_at is not None, "ActSummary.startedAt is a required field but was missing"
    assert ended_at >= started_at, (
        f"expected endedAt ({ended_at!r}) not to precede startedAt ({started_at!r})"
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
