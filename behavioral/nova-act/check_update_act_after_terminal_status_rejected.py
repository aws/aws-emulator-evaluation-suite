"""update-act-after-terminal-status-rejected."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-act-after-terminal-status-rejected"
GROUP = "overly-permissive"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAct to FAILED on an act already SUCCEEDED fails with ValidationException "Act in unexpected
    state" and leaves it SUCCEEDED; the identical call on a fresh act in the same session marks it
    FAILED."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    wf_name = _wf_name(ctx, "wfterm")
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
    nova.update_act(
        workflowDefinitionName=wf_name, workflowRunId=run_id, sessionId=session_id, actId=act_id, status="SUCCEEDED"
    )

    # Break exactly one thing: try to move the already-terminal act to FAILED -- a
    # validly-shaped target status, so the rejection can only be attributed to terminality,
    # not to an out-of-enum input value.
    error = _error_response(
        lambda: nova.update_act(
            workflowDefinitionName=wf_name,
            workflowRunId=run_id,
            sessionId=session_id,
            actId=act_id,
            status="FAILED",
            error={"message": "attempted transition after terminal", "type": "TestSetup"},
        )
    )
    code = error["Error"]["Code"]
    message = error["Error"]["Message"]
    assert code == "ValidationException", f"unexpected code: {code} ({message})"
    assert message == "Act in unexpected state", f"unexpected message: {message!r}"

    # Effect absent: the act is still recorded as SUCCEEDED, not FAILED.
    listed = nova.list_acts(workflowDefinitionName=wf_name, workflowRunId=run_id, sessionId=session_id)
    summary = next(s for s in listed["actSummaries"] if s["actId"] == act_id)
    assert summary["status"] == "SUCCEEDED"

    # Positive control, same file, identical call shape: a fresh (still-RUNNING) act
    # can be legitimately marked FAILED.
    other_act_id = nova.create_act(
        workflowDefinitionName=wf_name,
        workflowRunId=run_id,
        sessionId=session_id,
        task="Wait for further instructions before taking any action.",
        clientToken=_client_token(),
    )["actId"]
    nova.update_act(
        workflowDefinitionName=wf_name,
        workflowRunId=run_id,
        sessionId=session_id,
        actId=other_act_id,
        status="FAILED",
        error={"message": "attempted transition after terminal", "type": "TestSetup"},
    )
    listed2 = nova.list_acts(workflowDefinitionName=wf_name, workflowRunId=run_id, sessionId=session_id)
    other_summary = next(s for s in listed2["actSummaries"] if s["actId"] == other_act_id)
    assert other_summary["status"] == "FAILED"


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


def _error_response(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _silent(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
