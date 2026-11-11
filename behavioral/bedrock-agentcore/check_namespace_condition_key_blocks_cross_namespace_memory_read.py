"""namespace-condition-key-blocks-cross-namespace-memory-read."""
from __future__ import annotations

import datetime as _dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-condition-key-blocks-cross-namespace-memory-read"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore"]

_POLICY_NAME = "simparity-namespace-scope"
# Credential propagation symptoms for a freshly minted STS session. AccessDeniedException is
# deliberately NOT in this set: it is the authorization decision under test.
_CREDENTIAL_PROPAGATION = frozenset(
    {"InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException"}
)


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A principal granted ListMemoryRecords only under StringEquals on bedrock-agentcore:namespace
    lists its namespace but is denied a sibling namespace of the same memory, whose records an
    unrestricted read shows exist; broadening the condition to StringLike lets the call succeed."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    account_id = sts.get_caller_identity()["Account"]
    memory_id, memory_arn = _create_active_memory(ctx, control)
    assert account_id in memory_arn, (
        f"the memory ARN {memory_arn!r} does not name the calling account {account_id!r}"
    )

    # The policy conditions and the requests reuse these same namespace strings: the condition is
    # compared to the request's namespace parameter verbatim.
    tenant = ctx.unique_name("").replace("-", "")
    parent_ns = f"/simparity/{tenant}/actor/"
    ns_alpha = parent_ns + "alpha/facts/"
    ns_beta = parent_ns + "beta/facts/"

    now = _dt.datetime.now(_dt.timezone.utc)
    created = _poll_until(
        lambda: _batch_create_through_activation_gap(
            data,
            memory_id,
            [
                {
                    "requestIdentifier": "simparity-alpha",
                    "namespaces": [ns_alpha],
                    "content": {"text": f"alpha-fact-{tenant}"},
                    "timestamp": now,
                },
                {
                    "requestIdentifier": "simparity-beta",
                    "namespaces": [ns_beta],
                    "content": {"text": f"beta-fact-{tenant}"},
                    "timestamp": now,
                },
            ],
        ),
        lambda r: r is not None,
        timeout_s=45.0,
        interval_s=5.0,
        description="BatchCreateMemoryRecords accepted by the freshly-created memory",
    )
    assert created["failedRecords"] == [], (
        f"seeding the two namespaces failed: {created['failedRecords']!r}"
    )
    ids = {r["requestIdentifier"]: r["memoryRecordId"] for r in created["successfulRecords"]}
    assert set(ids) == {"simparity-alpha", "simparity-beta"}, (
        f"expected both records to be created, got {sorted(ids)!r}"
    )
    id_alpha = ids["simparity-alpha"]
    id_beta = ids["simparity-beta"]

    # Both records visible to the unrestricted caller before any authorization is exercised, so
    # a later denial is a denial rather than an empty store.
    _poll_until(
        lambda: _listed_ids(data, memoryId=memory_id, namespacePath=parent_ns),
        lambda seen: {id_alpha, id_beta} <= seen,
        timeout_s=30.0,
        interval_s=3.0,
        description="both seeded records are listable to the unrestricted caller",
    )

    role_name, role_arn = _create_assumable_role(ctx, iam, account_id)
    _grant(
        iam,
        role_name,
        memory_arn,
        {"StringEquals": {"bedrock-agentcore:namespace": ns_alpha}},
    )
    restricted = _client_for_role(ctx, sts, role_arn, "bedrock-agentcore")

    # BEAT 1 — positive control: the grant works for the namespace it names. Retried only for
    # IAM/credential propagation, with a bounded poll that RAISES.
    allowed = _poll_until(
        lambda: _outcome(
            lambda: restricted.list_memory_records(
                memoryId=memory_id, namespace=ns_alpha, maxResults=100
            )
        ),
        lambda out: out["code"] not in _CREDENTIAL_PROPAGATION
        and out["code"] != "AccessDeniedException",
        timeout_s=90.0,
        interval_s=5.0,
        description=(
            f"the restricted principal's grant on namespace {ns_alpha} became effective"
        ),
    )
    assert allowed["code"] is None, (
        f"the positive control failed: the restricted principal was refused {allowed['code']!r} "
        f"on the namespace its policy explicitly allows ({ns_alpha!r}). Without this beat, the "
        "denial below is indistinguishable from denying everything"
    )
    allowed_ids = {
        s["memoryRecordId"] for s in allowed["result"]["memoryRecordSummaries"]
    }
    assert allowed_ids == {id_alpha}, (
        f"the permitted read returned {sorted(allowed_ids)!r}, expected exactly [{id_alpha!r}]"
    )

    # BEAT 2/3 — break exactly one thing (the namespace argument) and assert the specific code.
    denied = _outcome(
        lambda: restricted.list_memory_records(
            memoryId=memory_id, namespace=ns_beta, maxResults=100
        )
    )
    assert denied["code"] == "AccessDeniedException", (
        f"listing the sibling namespace {ns_beta!r} returned {denied['code']!r} "
        f"(result={denied['result']!r}), expected 'AccessDeniedException'. The policy's only "
        f"Allow is conditioned on bedrock-agentcore:namespace == {ns_alpha!r}; a target that "
        "authorizes on action and resource alone lets this through"
    )
    assert denied["message"] == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/simparity-ns-scope is not "
        "authorized to perform this operation"
    ), f"expected the exact namespace-condition denial message, got {denied['message']!r}"

    # BEAT 4 — effect absent, via an independent read by a DIFFERENT principal: beta's record
    # does exist and is readable, so the denial hid data rather than there being none.
    unrestricted_beta = _listed_ids(data, memoryId=memory_id, namespace=ns_beta)
    assert unrestricted_beta == {id_beta}, (
        f"the unrestricted caller sees {sorted(unrestricted_beta)!r} under {ns_beta!r}, expected "
        f"exactly [{id_beta!r}] — the denial above must be hiding a record that is really there"
    )

    # BEAT 5 — restore: broaden the condition to cover the whole parent hierarchy.
    _grant(
        iam,
        role_name,
        memory_arn,
        {"StringLike": {"bedrock-agentcore:namespace": parent_ns + "*"}},
    )

    # BEAT 6 — the IDENTICAL call now succeeds, and its terminal read is at the destination
    # through the restricted principal itself.
    restored = _poll_until(
        lambda: _outcome(
            lambda: restricted.list_memory_records(
                memoryId=memory_id, namespace=ns_beta, maxResults=100
            )
        ),
        lambda out: out["code"] is None,
        timeout_s=90.0,
        interval_s=5.0,
        description=(
            f"broadening the condition to StringLike {parent_ns}* let the identical "
            f"ListMemoryRecords(namespace={ns_beta}) succeed"
        ),
    )
    restored_ids = {
        s["memoryRecordId"] for s in restored["result"]["memoryRecordSummaries"]
    }
    assert restored_ids == {id_beta}, (
        f"after the restore, the same principal's same call returned {sorted(restored_ids)!r}, "
        f"expected exactly [{id_beta!r}]"
    )
    # And the broadened grant did not become a blanket grant: alpha is still scoped to alpha.
    still_alpha = _outcome(
        lambda: restricted.list_memory_records(
            memoryId=memory_id, namespace=ns_alpha, maxResults=100
        )
    )
    assert still_alpha["code"] is None, (
        f"the broadened grant refused {ns_alpha!r} with {still_alpha['code']!r}"
    )
    still_alpha_ids = {
        s["memoryRecordId"] for s in still_alpha["result"]["memoryRecordSummaries"]
    }
    assert still_alpha_ids == {id_alpha}, (
        f"reading {ns_alpha!r} under the broadened grant returned {sorted(still_alpha_ids)!r}, "
        f"expected exactly [{id_alpha!r}] — widening the CONDITION must not widen what each "
        "namespace scope returns"
    )



# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously. The
# runner swallows a cleanup's exception, so a bare delete in on_cleanup leaked even on PASS.
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


def _create_active_memory(ctx, control) -> tuple[str, str]:
    name = "simparityns" + ctx.unique_name("").replace("-", "")[:24]
    memory = control.create_memory(
        name=name,
        eventExpiryDuration=7,
        tags={"simparity": CHECK, "simparity-owner": "simparity-behavioral"},
    )["memory"]
    memory_arn = memory["arn"]
    memory_id = memory.get("id") or memory_arn.rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    status = _poll_until(
        lambda: control.get_memory(memoryId=memory_id)["memory"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "FAILED"),
        # 240s: a new memory with a strategy can stay CREATING for well over 90s.
        timeout_s=240.0,
        interval_s=5.0,
        description=f"memory {memory_id} left CREATING",
    )
    assert status == "ACTIVE", (
        f"memory {memory_id} reached terminal status {status!r}, expected 'ACTIVE'"
    )
    return memory_id, memory_arn


def _create_assumable_role(ctx, iam, account_id) -> tuple[str, str]:
    role_name = ctx.unique_name("simparity-ns-scope-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "simparity", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME)
    )
    return role_name, role_arn


def _grant(iam, role_name, memory_arn, condition) -> None:
    """Replace the role's ONLY inline policy with a single conditioned Allow."""
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=_POLICY_NAME,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "SimparityNamespaceScope",
                        "Effect": "Allow",
                        "Action": "bedrock-agentcore:ListMemoryRecords",
                        "Resource": memory_arn,
                        "Condition": condition,
                    }
                ],
            }
        ),
    )


def _client_for_role(ctx, sts, role_arn, service):
    """A client signing AS the minted role, built through ctx.client's `creds` override so it
    keeps THIS target's endpoint and TLS wiring. A hand-rolled boto3.client here would send the
    asserted request to real AWS even when the target is an emulator."""
    creds = _poll_until(
        lambda: _outcome(
            lambda: sts.assume_role(
                RoleArn=role_arn, RoleSessionName="simparity-ns-scope"
            )
        ),
        lambda out: out["code"] is None,
        timeout_s=30.0,
        interval_s=3.0,
        description=f"role {role_arn} became assumable",
    )["result"]["Credentials"]
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _batch_create_through_activation_gap(data, memory_id, records):
    """The batch write, or None while the memory reports ACTIVE but does not yet accept writes.

    Only the specific activation-gap refusal is absorbed; every other ClientError propagates.
    """
    try:
        return data.batch_create_memory_records(memoryId=memory_id, records=records)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ValidationException" and "not active" in str(
            err.get("Message", "")
        ):
            return None
        raise


def _outcome(fn):
    """Both halves of one attempt: {"code": None, "message": None, "result": ...} on success, or
    {"code": "<AWS error code>", "message": "<AWS error message>", "result": None}.

    Unlike a bare `_error_code` helper this cannot turn an unexpected success into a falsy
    sentinel — every caller asserts explicitly on `code`, including asserting it IS None.
    """
    try:
        return {"code": None, "message": None, "result": fn()}
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return {"code": error.get("Code"), "message": error.get("Message"), "result": None}


def _listed_ids(data, **kwargs) -> set[str]:
    """Every memoryRecordId ListMemoryRecords reports. `memoryRecordSummaries` is REQUIRED in the
    output shape, so it is hard-subscripted rather than defaulted."""
    ids: set[str] = set()
    token = None
    for _ in range(20):
        params = dict(kwargs, maxResults=100)
        if token:
            params["nextToken"] = token
        resp = data.list_memory_records(**params)
        ids.update(s["memoryRecordId"] for s in resp["memoryRecordSummaries"])
        token = resp.get("nextToken")
        if not token:
            return ids
    raise AssertionError(
        f"ListMemoryRecords({kwargs!r}) did not stop paginating after 20 pages ({len(ids)} ids)"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout and never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
