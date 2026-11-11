"""invoke-act-step-call-id-mismatch-rejected."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "invoke-act-step-call-id-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeActStep rejects a callResults entry whose callId does not match any
    outstanding tool call (there are none yet, since no step has ever been invoked)."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    wf_name = _wf_name(ctx, "wfmis")
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
        task="Wait for further instructions before taking any action.",
        clientToken=_client_token(),
    )["actId"]

    bogus_call_id = "call-that-was-never-issued"
    err = _client_error(
        lambda: nova.invoke_act_step(
            workflowDefinitionName=wf_name,
            workflowRunId=run_id,
            sessionId=session_id,
            actId=act_id,
            callResults=[{"callId": bogus_call_id, "content": [{"text": "ok"}]}],
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException for an unmatched callId, got {err!r}"
    assert err.get("Message") == "The provided input is invalid or malformed.", (
        f"expected the exact invalid-input message, got {err.get('Message')!r}"
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


def _client_error(fn):
    """Call fn() and return its ClientError's ``Error`` dict (``Code``, ``Message``). An unexpected
    success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _silent(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
