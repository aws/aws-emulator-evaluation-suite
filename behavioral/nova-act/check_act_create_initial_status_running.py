"""act-create-initial-status-running."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "act-create-initial-status-running"
GROUP = "state"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAct returns a non-terminal status before any step has been invoked, and
    that status is independently confirmed via ListActs, not just the create response."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    wf_name = _wf_name(ctx, "wfact")
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

    created = nova.create_act(
        workflowDefinitionName=wf_name,
        workflowRunId=run_id,
        sessionId=session_id,
        task="Wait for further instructions before taking any action.",
        clientToken=_client_token(),
    )
    act_id = created["actId"]
    assert re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", act_id)
    assert created["status"] in ("RUNNING", "PENDING_CLIENT_ACTION", "PENDING_HUMAN_ACTION"), (
        f"expected a non-terminal initial status from CreateAct itself, got {created['status']!r}"
    )

    # The terminal assertion must be an independent read, not the mutating call's
    # own response — ListActs is the only reader Nova Act exposes for an act's status.
    resp = nova.list_acts(workflowDefinitionName=wf_name, workflowRunId=run_id, sessionId=session_id)
    summary = next((a for a in resp["actSummaries"] if a["actId"] == act_id), None)
    assert summary is not None, f"act {act_id} not visible via independent ListActs read"
    assert summary["status"] in ("RUNNING", "PENDING_CLIENT_ACTION", "PENDING_HUMAN_ACTION"), (
        f"expected non-terminal status via independent ListActs read, got {summary['status']!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
