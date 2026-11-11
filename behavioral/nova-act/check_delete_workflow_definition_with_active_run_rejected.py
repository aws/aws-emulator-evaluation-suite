"""delete-workflow-definition-with-active-run-rejected."""
from __future__ import annotations

import re
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-workflow-definition-with-active-run-rejected"
GROUP = "overly-permissive"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorkflowDefinition succeeds while a run is RUNNING; afterwards GetWorkflowDefinition and
    CreateWorkflowRun under that name fail with ResourceNotFoundException "Workflow definition not
    found", while a run under a live definition starts RUNNING."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    wf_name = _wf_name(ctx, "wfdel")
    nova.create_workflow_definition(name=wf_name, clientToken=_client_token())

    model_id, version = _pick_model(nova)
    run_id = nova.create_workflow_run(
        workflowDefinitionName=wf_name,
        modelId=model_id,
        clientToken=_client_token(),
        clientInfo={"compatibilityVersion": version, "sdkVersion": "sim2real-behavioral-1.0"},
    )["workflowRunId"]
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_run(workflowDefinitionName=wf_name, workflowRunId=run_id)))

    # Delete while the run is still RUNNING: AWS accepts it (the definition does not require
    # its runs to be terminal first).
    nova.delete_workflow_definition(workflowDefinitionName=wf_name)

    def _definition_listed():
        pages = nova.get_paginator("list_workflow_definitions").paginate()
        return any(d["workflowDefinitionName"] == wf_name for page in pages for d in page["workflowDefinitionSummaries"])

    _poll_until(_definition_listed, lambda listed: not listed, timeout_s=120.0, interval_s=3.0)
    err = _client_error(lambda: nova.get_workflow_definition(workflowDefinitionName=wf_name))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected GetWorkflowDefinition to report ResourceNotFoundException after delete, got {err!r}"
    )
    assert err.get("Message") == "Workflow definition not found", (
        f"expected the exact not-found message after delete, got {err.get('Message')!r}"
    )

    # Break exactly one thing: try to create a NEW run under the now-deleted definition.
    create_err = _client_error(
        lambda: nova.create_workflow_run(
            workflowDefinitionName=wf_name,
            modelId=model_id,
            clientToken=_client_token(),
            clientInfo={"compatibilityVersion": version, "sdkVersion": "sim2real-behavioral-1.0"},
        )
    )
    assert create_err["Code"] == "ResourceNotFoundException", (
        f"expected CreateWorkflowRun under a deleted definition to be rejected with ResourceNotFoundException, "
        f"got {create_err!r}"
    )
    assert create_err.get("Message") == "Workflow definition not found", (
        f"expected the exact not-found message for CreateWorkflowRun, got {create_err.get('Message')!r}"
    )

    # Positive control, same file: a fresh, still-ACTIVE definition accepts a new run.
    other_name = _wf_name(ctx, "wfdelok")
    nova.create_workflow_definition(name=other_name, clientToken=_client_token())
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=other_name)))
    other_run_id = nova.create_workflow_run(
        workflowDefinitionName=other_name,
        modelId=model_id,
        clientToken=_client_token(),
        clientInfo={"compatibilityVersion": version, "sdkVersion": "sim2real-behavioral-1.0"},
    )["workflowRunId"]
    ctx.on_cleanup(
        lambda: _silent(lambda: nova.delete_workflow_run(workflowDefinitionName=other_name, workflowRunId=other_run_id))
    )
    other_status = nova.get_workflow_run(workflowDefinitionName=other_name, workflowRunId=other_run_id)["status"]
    assert other_status == "RUNNING", f"expected the positive control's fresh run to be RUNNING under its still-ACTIVE definition, got {other_status!r}"


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
