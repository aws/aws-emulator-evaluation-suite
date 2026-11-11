"""create-session-idempotent-same-token."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-session-idempotent-same-token"
GROUP = "idempotency"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSession called twice with the same clientToken and identical parameters
    returns the same sessionId instead of creating a second session."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    wf_name = _wf_name(ctx, "wfsi")
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

    token = _client_token()
    first = nova.create_session(workflowDefinitionName=wf_name, workflowRunId=run_id, clientToken=token)
    second = nova.create_session(workflowDefinitionName=wf_name, workflowRunId=run_id, clientToken=token)

    assert first["sessionId"] == second["sessionId"], "same clientToken+params must be idempotent"

    listed = nova.list_sessions(workflowDefinitionName=wf_name, workflowRunId=run_id)
    matching = [s for s in listed["sessionSummaries"] if s["sessionId"] == first["sessionId"]]
    assert len(matching) == 1, "idempotent replay must not create a second session resource"


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
