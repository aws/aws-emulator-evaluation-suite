"""session-cross-workflow-run-isolation-rejected."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "session-cross-workflow-run-isolation-rejected"
GROUP = "overly-permissive"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAct addressed to run B with run A's sessionId fails with ResourceNotFoundException "Session
    not found" and adds nothing to run B's sessions; the same session with its own run A creates an act."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    wf_name = _wf_name(ctx, "wfiso")
    nova.create_workflow_definition(name=wf_name, clientToken=_client_token())
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=wf_name)))

    model_id, version = _pick_model(nova)

    def _new_run():
        rid = nova.create_workflow_run(
            workflowDefinitionName=wf_name,
            modelId=model_id,
            clientToken=_client_token(),
            clientInfo={"compatibilityVersion": version, "sdkVersion": "sim2real-behavioral-1.0"},
        )["workflowRunId"]
        ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_run(workflowDefinitionName=wf_name, workflowRunId=rid)))
        return rid

    run_a = _new_run()
    run_b = _new_run()

    session_a = nova.create_session(
        workflowDefinitionName=wf_name, workflowRunId=run_a, clientToken=_client_token()
    )["sessionId"]

    # Break exactly one thing: address run B's path, but use run A's sessionId.
    err = _client_error(
        lambda: nova.create_act(
            workflowDefinitionName=wf_name,
            workflowRunId=run_b,
            sessionId=session_a,
            task="Wait for further instructions before taking any action.",
            clientToken=_client_token(),
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    assert err.get("Message") == "Session not found", f"expected the exact not-found message, got {err.get('Message')!r}"

    # Effect absent: run B has no acts/sessions of its own from this attempt.
    sessions_b = nova.list_sessions(workflowDefinitionName=wf_name, workflowRunId=run_b)
    sessions_b_ids = [s["sessionId"] for s in sessions_b["sessionSummaries"]]
    assert session_a not in sessions_b_ids, f"session {session_a} leaked into run B's sessions: {sessions_b_ids}"

    # Positive control, same file: session A used with its own run A succeeds.
    act_id = nova.create_act(
        workflowDefinitionName=wf_name,
        workflowRunId=run_a,
        sessionId=session_a,
        task="Wait for further instructions before taking any action.",
        clientToken=_client_token(),
    )["actId"]
    listed = nova.list_acts(workflowDefinitionName=wf_name, workflowRunId=run_a, sessionId=session_a)
    listed_ids = [a["actId"] for a in listed["actSummaries"]]
    assert act_id in listed_ids, f"expected act {act_id} in run A's acts, got {listed_ids}"


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
