"""e2e-memory-extraction-to-retrieval."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-memory-extraction-to-retrieval"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]

_EXTRACTION_TERMINAL = {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After IngestData, AgentCore Memory's asynchronous extraction yields a record that
    RetrieveMemoryRecords returns for the ingested fact, and after DeleteMemoryRecord
    GetMemoryRecord returns ResourceNotFoundException ('The memory record was not found').
    """
    iam = ctx.client("iam")
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    role_arn = _create_memory_execution_role(ctx, iam)
    memory_id = _create_memory(ctx, control, role_arn)
    _wait_for_memory_active(control, memory_id, timeout_s=180.0)

    actor_id = ctx.unique_name("sim2real-actor-").replace("-", "_")
    marker = ctx.unique_name("sim2real-mem-")
    passphrase = f"quetzal-{marker}"
    fact_text = f"The onboarding passphrase for project {marker} is {passphrase}. Remember this fact."

    data.ingest_data(
        memoryId=memory_id,
        source={"inline": {"payload": [{"conversational": {"content": {"text": fact_text}, "role": "USER"}}]}},
        contentTimestamp=datetime.now(timezone.utc),
        actorId=actor_id,
    )

    job = _poll_for_extraction_job(data, memory_id, timeout_s=60.0)
    if job is not None and job.get("status") not in _EXTRACTION_TERMINAL:
        # Best-effort: explicitly (re)start the discovered job. If the pipeline already
        # auto-started it from IngestData alone, the service is expected to reject this as a
        # no-op / invalid-state request rather than corrupt anything.
        try:
            data.start_memory_extraction_job(memoryId=memory_id, extractionJob={"jobId": job["jobID"]})
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ValidationException", "AccessDeniedException"):
                raise

    namespace = f"/semantic/{actor_id}"
    records = _poll_for_matching_record(data, memory_id, namespace, passphrase, timeout_s=300.0)
    assert records, "RetrieveMemoryRecords never surfaced a record reflecting the ingested fact"
    record_id = records[0]["memoryRecordId"]

    data.delete_memory_record(memoryId=memory_id, memoryRecordId=record_id)
    code, message = _error(lambda: data.get_memory_record(memoryId=memory_id, memoryRecordId=record_id))
    assert code == "ResourceNotFoundException", code
    assert message == "The memory record was not found", (
        f"expected message 'The memory record was not found', got {message!r}"
    )


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously, so a
# teardown waits out the transitional status and then for ResourceNotFoundException.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_memory(control, memory_id):
    _ac_delete_and_wait(
        lambda: control.get_memory(memoryId=memory_id)["memory"]["status"],
        lambda: control.delete_memory(memoryId=memory_id),
        what=f"memory {memory_id}",
    )

def _create_memory_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-agentcore-memory-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_memory(ctx, control, role_arn, timeout_s=90.0, interval_s=5.0):
    name = ctx.unique_name("Sim2RealMemory")[:48].replace("-", "")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = control.create_memory(
                name=name,
                eventExpiryDuration=7,
                memoryExecutionRoleArn=role_arn,
                memoryStrategies=[{
                    "semanticMemoryStrategy": {
                        "name": "sim2real_semantic",
                        "namespaceTemplates": ["/semantic/{actorId}"],
                    }
                }],
            )
            memory_id = resp["memory"]["id"] if "id" in resp["memory"] else resp["memory"]["memoryId"]
            ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))
            return memory_id
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _wait_for_memory_active(control, memory_id, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = control.get_memory(memoryId=memory_id)["memory"]["status"]
        if status == "ACTIVE":
            return
        if status in ("CREATE_FAILED", "FAILED"):
            raise AssertionError(f"memory reached terminal failure status {status!r}")
        time.sleep(interval_s)
    raise AssertionError(f"memory never reached ACTIVE within {timeout_s}s (last status={status!r})")


def _poll_for_extraction_job(data, memory_id, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = data.list_memory_extraction_jobs(memoryId=memory_id).get("jobs", [])
        if jobs:
            return jobs[0]
        time.sleep(interval_s)
    return None


def _poll_for_matching_record(data, memory_id, namespace, needle, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = data.retrieve_memory_records(
            memoryId=memory_id,
            namespace=namespace,
            searchCriteria={"searchQuery": needle, "topK": 5},
        )
        matches = [
            r for r in resp.get("memoryRecordSummaries", [])
            if needle in json.dumps(r.get("content", {}))
        ]
        if matches:
            return matches
        time.sleep(interval_s)
    return []


def _error(fn):
    """The (code, message) of the ClientError fn raises. An unexpected SUCCESS raises, so a
    target that still serves a deleted record fails naming what it returned."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
