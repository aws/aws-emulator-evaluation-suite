"""update-act-invalid-status-enum-rejected."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-act-invalid-status-enum-rejected"
GROUP = "error-semantics"
SERVICES = ["nova-act"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAct rejects a status value outside the ActStatus enum with ValidationException,
    and the act's real status is left untouched. A positive control on a separate act in the
    same session proves UpdateAct accepts a valid status transition on this same wiring."""
    nova = _nova_client(ctx)
    wf_name = _wf_name(ctx, "wfenum")
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

    # Positive control, same wiring: a valid status value is accepted and takes effect.
    control_act_id = nova.create_act(
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
        actId=control_act_id,
        status="SUCCEEDED",
    )
    control_listed = nova.list_acts(workflowDefinitionName=wf_name, workflowRunId=run_id, sessionId=session_id)
    control_summary = next(s for s in control_listed["actSummaries"] if s["actId"] == control_act_id)
    assert control_summary["status"] == "SUCCEEDED", (
        f"positive control failed: expected SUCCEEDED, got {control_summary['status']!r}"
    )

    # Break exactly one thing: a status value outside the ActStatus enum, on a fresh act.
    created = nova.create_act(
        workflowDefinitionName=wf_name,
        workflowRunId=run_id,
        sessionId=session_id,
        task="Wait for further instructions before taking any action.",
        clientToken=_client_token(),
    )
    act_id = created["actId"]
    initial_status = created["status"]

    code, message = _error(
        lambda: nova.update_act(
            workflowDefinitionName=wf_name,
            workflowRunId=run_id,
            sessionId=session_id,
            actId=act_id,
            status="NOT_A_REAL_STATUS",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value at 'status' failed to satisfy constraint: Member must "
        "satisfy enum value set: [SUCCEEDED, PENDING_CLIENT_ACTION, TIMED_OUT, PENDING_HUMAN_ACTION, "
        "FAILED, RUNNING]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listed = nova.list_acts(workflowDefinitionName=wf_name, workflowRunId=run_id, sessionId=session_id)
    summary = next(s for s in listed["actSummaries"] if s["actId"] == act_id)
    assert summary["status"] == initial_status, (
        f"rejected update must not have changed the act's status: expected {initial_status!r}, got {summary['status']!r}"
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


def _error(fn):
    """The (code, message) of the refusal ``fn`` provokes; raises if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
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
