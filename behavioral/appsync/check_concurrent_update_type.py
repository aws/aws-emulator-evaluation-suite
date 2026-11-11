"""concurrent-update-type."""
from __future__ import annotations

import concurrent.futures
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results in submission order — each entry is the callable's
    return value or the Exception it raised (captured, NOT re-raised)."""
    results = [None] * len(fns)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                idx = future_to_idx[fut]
                try:
                    results[idx] = fut.result()
                except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
                    results[idx] = exc
        except concurrent.futures.TimeoutError:
            for pending, i in future_to_idx.items():
                if not pending.done():
                    results[i] = concurrent.futures.TimeoutError(f"call did not finish within {timeout_s}s")
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

def _successes(results):
    return sum(1 for r in results if not isinstance(r, BaseException))

def _error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

def _delete_if_present(fn):
    """Teardown for a resource the check's own delete race may already have removed."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _list_all(call, items_key, **params):
    """Paginate any AppSync ``List*`` call (all use ``nextToken``) and return the concatenated items."""
    results = []
    next_token = None
    while True:
        kwargs = dict(params)
        if next_token:
            kwargs["nextToken"] = next_token
        resp = call(**kwargs)
        results.extend(resp.get(items_key, []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return results

# A losing schema writer reads one of these, depending on which in-flight guard it hits.
_SCHEMA_BUSY_MESSAGES = (
    "Schema is currently being altered, please wait until that is complete.",
    "Schema or API is currently being altered, please wait until that is complete.",
    "Type locked due to concurrent update, please retry",
)

def _assert_update_race(results, *, racers, op_name, expected_code="ConcurrentModificationException"):
    successes = _successes(results)
    codes = _error_codes(results)
    assert successes >= 1, f"expected at least one {op_name} racer to win, got results={results!r}"
    assert successes + len(codes) == racers, (
        f"every {op_name} racer must resolve to either a success or an error, got {results!r}"
    )
    for code in codes:
        assert code == expected_code, (
            f"expected every losing {op_name} racer to fail with {expected_code}, got {code} "
            f"(all codes: {codes!r})"
        )
    for r in results:
        if isinstance(r, ClientError):
            msg = r.response.get("Error", {}).get("Message")
            assert msg in _SCHEMA_BUSY_MESSAGES, f"unexpected losing {op_name} {expected_code} message: {msg!r}"
    return successes

def _assert_delete_race(results, *, op_name, allowed_codes=("NotFoundException", "ConcurrentModificationException")):
    successes = _successes(results)
    codes = _error_codes(results)
    assert successes == 1, f"expected exactly 1 {op_name} racer to win, got {successes} (results={results!r})"
    for code in codes:
        assert code in allowed_codes, (
            f"expected every losing {op_name} racer to fail with one of {allowed_codes}, got {code}"
        )

def _create_merged_api(ctx, svc):
    """Create a MERGED-type GraphQL API — the target of source API associations. Real AppSync
    REQUIRES a mergedApiExecutionRoleArn for apiType=MERGED even under MANUAL_MERGE, so provision a
    throwaway IAM role; teardown for both the role and the api is registered."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-appsync-merge-role-")[:64]
    def _teardown_role(rn=role, _iam=iam):
        for pn in _iam.list_role_policies(RoleName=rn).get("PolicyNames", []):
            _iam.delete_role_policy(RoleName=rn, PolicyName=pn)
        _iam.delete_role(RoleName=rn)
    ctx.on_cleanup(_teardown_role)
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    iam.put_role_policy(RoleName=role, PolicyName="merge", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["appsync:SourceGraphQL", "appsync:StartSchemaMerge", "appsync:GetSourceApiAssociation"], "Resource": "*"}]}))
    merged_name = ctx.unique_name("sim2real-behav-appsync-merged-")
    deadline = time.monotonic() + 60.0
    last_exc = None
    merged = None
    while time.monotonic() < deadline:
        try:
            merged = svc.create_graphql_api(
                name=merged_name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )["graphqlApi"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3.0)
    if merged is None:
        raise AssertionError(f"create_graphql_api(MERGED) never succeeded within 60s of IAM role trust propagation retries: {last_exc}")
    ctx.on_cleanup(lambda _a=merged: svc.delete_graphql_api(apiId=_a["apiId"]))
    return merged

CHECK = "concurrent-update-type"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent update/delete of the same Type serialize: a losing racer fails with ConcurrentModificationException
    and its write never persists; ListTypesByAssociation's referential-integrity boundary is also graded."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    svc.start_schema_creation(apiId=api_id, definition="schema { query: Query }\ntype Query { ping: String }".encode("utf-8"))
    # settle before creating a type (schema creation must not be in flight)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        status = svc.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"):
            break
        time.sleep(2.0)
    else:
        raise AssertionError(f"schema creation for apiId={api_id} did not settle within 90s")

    type_name = "Widget" + ctx.unique_name("")[-8:]
    svc.create_type(apiId=api_id, definition=f"type {type_name} {{ id: ID }}", format="SDL")
    ctx.on_cleanup(lambda: _delete_if_present(lambda: svc.delete_type(apiId=api_id, typeName=type_name)))
    racers = 5

    def update_attempt(i):
        return svc.update_type(
            apiId=api_id,
            typeName=type_name,
            format="SDL",
            definition=f"type {type_name} {{ id: ID f{i}: String }}",
        )

    results = _run_concurrent([lambda i=i: update_attempt(i) for i in range(racers)])
    _assert_update_race(results, racers=racers, op_name="UpdateType")

    got = svc.get_type(apiId=api_id, typeName=type_name, format="SDL")["type"]
    assert "String" in got["definition"], f"expected the winning UpdateType to persist, got {got!r}"
    winners = {f"f{i}" for i, r in enumerate(results) if not isinstance(r, BaseException)}
    persisted = set(re.findall(r"\b(f\d+)\s*:", got["definition"]))
    assert len(persisted) == 1 and persisted <= winners, (
        f"expected exactly one successful racer's field (one of {sorted(winners)}) to persist and no losing "
        f"racer's write, got fields {sorted(persisted)} in {got['definition']!r}"
    )

    names = {t["name"] for t in _list_all(lambda **kw: svc.list_types(apiId=api_id, format="SDL", **kw), "types")}
    assert type_name in names, "the type must remain discoverable via ListTypes throughout the race"

    # ListTypesByAssociation referential-integrity boundary: a real merged API exists (so
    # mergedApiIdentifier resolves), but the associationId is bogus.
    merged = _create_merged_api(ctx, svc)
    assoc_code, assoc_message = _error(
        lambda: svc.list_types_by_association(
            associationId="00000000-0000-0000-0000-000000000000",
            mergedApiIdentifier=merged["apiId"],
            format="SDL",
        )
    )
    assert assoc_code == "NotFoundException", (
        f"expected NotFoundException for ListTypesByAssociation with a bogus associationId, got {assoc_code}"
    )
    assert assoc_message == "No source API association was found", (
        f"expected the exact NotFound message from ListTypesByAssociation, got {assoc_message!r}"
    )

    del_results = _run_concurrent(
        [lambda: svc.delete_type(apiId=api_id, typeName=type_name) for _ in range(3)]
    )
    _assert_delete_race(del_results, op_name="DeleteType")

    code_after, message_after = _error(lambda: svc.get_type(apiId=api_id, typeName=type_name, format="SDL"))
    assert code_after == "NotFoundException", (
        f"expected NotFoundException from GetType after the delete race settled, got {code_after}"
    )
    assert message_after == "Type not found.", (
        f"expected the exact NotFound message from GetType, got {message_after!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
