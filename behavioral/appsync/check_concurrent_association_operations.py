"""concurrent-association-operations."""
from __future__ import annotations

import concurrent.futures
import json
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

def _errors(results):
    """The (code, message) of every failed result; a non-ClientError keeps its type name."""
    errors = []
    for r in results:
        if isinstance(r, ClientError):
            errors.append((r.response["Error"]["Code"], r.response["Error"].get("Message")))
        elif isinstance(r, BaseException):
            errors.append((type(r).__name__, str(r)))
    return errors

def _association_error(svc, association_id, merged_id):
    """GetSourceApiAssociation's (code, message) once it fails; ("present", None) while it resolves."""
    try:
        svc.get_source_api_association(associationId=association_id, mergedApiIdentifier=merged_id)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "present", None

_ASSOCIATION_NOT_FOUND = "No source API association was found"
_DISASSOCIATE_RACE_MESSAGES = {
    "NotFoundException": _ASSOCIATION_NOT_FOUND,
    "ConcurrentModificationException": (
        "This association currently has an operation in progress, please wait until that is complete"
    ),
}


def _association_race_messages(merged_id):
    """The exact refusal per code for a losing Associate*GraphqlApi racer on ``merged_id``.

    message varies: a BadRequestException loser reads either "SourceApiAssociation already
    exists." or "Source Api can not be associated with multiple Merged APIs." depending on how far
    the winner got, so only its code is graded (None).
    """
    return {
        "ConcurrentModificationException": (
            f"SourceApiAssociations for Merged API {merged_id} are currently being updated, "
            "please wait and try again."
        ),
        "BadRequestException": None,
    }


def _source_association_ids(svc, merged_id, source_id):
    """Association ids ListSourceApiAssociations reports on ``merged_id`` for ``source_id``."""
    ids = []
    for page in svc.get_paginator("list_source_api_associations").paginate(apiId=merged_id):
        ids += [s["associationId"] for s in page.get("sourceApiAssociationSummaries", []) if s.get("sourceApiId") == source_id]
    return ids


def _ignore_not_found(fn):
    """Teardown for an association a disassociation racer may already have removed."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _create_graphql_api(ctx, svc):
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    return api

def _create_merged_api(ctx, svc):
    """Create a MERGED-type GraphQL API. Real AppSync REQUIRES a mergedApiExecutionRoleArn for
    apiType=MERGED even under MANUAL_MERGE, so provision a throwaway IAM role; teardown for both the
    role and the api is registered. IAM's trust-policy propagation is eventually consistent, so the
    first CreateGraphqlApi(apiType=MERGED) attempt can transiently see the role as unusable
    (BadRequestException) -- retry it on a bounded deadline instead of asserting on a hardcoded delay."""
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

    name = ctx.unique_name("sim2real-behav-appsync-merged-")
    deadline = time.monotonic() + 30
    last_exc = None
    while time.monotonic() < deadline:
        try:
            merged = svc.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )["graphqlApi"]
            ctx.on_cleanup(lambda _a=merged: svc.delete_graphql_api(apiId=_a["apiId"]))
            return merged
        except ClientError as exc:
            last_exc = exc
            if exc.response.get("Error", {}).get("Code") == "BadRequestException":
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create merged API after role propagation wait: {last_exc}")

CHECK = "concurrent-association-operations"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overlapping associate/disassociate calls for merged or source graphql APIs surface
    ConcurrentModificationException; the DisassociateApi referential-integrity boundary is also
    verified under concurrency."""
    svc = ctx.client("appsync")
    source1 = _create_graphql_api(ctx, svc)
    source1_id = source1["apiId"]
    merged = _create_merged_api(ctx, svc)
    merged_id = merged["apiId"]

    # --- source-initiated race: concurrent AssociateMergedGraphqlApi for the SAME (source, merged) pair.
    assoc_racers = 4

    def assoc_attempt():
        return svc.associate_merged_graphql_api(
            sourceApiIdentifier=source1_id,
            mergedApiIdentifier=merged_id,
            sourceApiAssociationConfig={"mergeType": "MANUAL_MERGE"},
        )

    results = _run_concurrent([assoc_attempt for _ in range(assoc_racers)])
    successes = [r for r in results if not isinstance(r, BaseException)]
    errors = _errors(results)
    assert len(successes) >= 1, f"expected at least one AssociateMergedGraphqlApi racer to win, got {results!r}"
    assert len(successes) + len(errors) == assoc_racers
    assoc_messages = _association_race_messages(merged_id)
    for code, msg in errors:
        assert code in assoc_messages, (
            f"expected losing AssociateMergedGraphqlApi racers to fail with a state-conflict code, got {code}"
        )
        if assoc_messages[code] is not None:
            assert msg == assoc_messages[code], f"unexpected {code} message: {msg!r}"
    association_id = successes[0]["sourceApiAssociation"]["associationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: svc.disassociate_merged_graphql_api(sourceApiIdentifier=source1_id, associationId=association_id)))
    listed = _source_association_ids(svc, merged_id, source1_id)
    assert listed == [association_id], (
        f"expected the racing AssociateMergedGraphqlApi calls to leave exactly one association {association_id!r}, listed {listed!r}"
    )

    # Let the initial auto-fired merge settle (best effort) before racing disassociation.
    _poll_until(
        lambda: svc.get_source_api_association(associationId=association_id, mergedApiIdentifier=merged_id)["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] not in ("MERGE_SCHEDULED", "MERGE_IN_PROGRESS"),
        timeout_s=90, interval_s=3.0,
        description="initial merge to settle before racing DisassociateMergedGraphqlApi",
    )

    del_results = _run_concurrent(
        [lambda: svc.disassociate_merged_graphql_api(sourceApiIdentifier=source1_id, associationId=association_id) for _ in range(3)]
    )
    del_successes = _successes(del_results)
    del_errors = _errors(del_results)
    assert del_successes >= 1, f"expected at least one DisassociateMergedGraphqlApi racer to win, got {del_results!r}"
    for code, msg in del_errors:
        assert code in _DISASSOCIATE_RACE_MESSAGES, (
            f"expected losing DisassociateMergedGraphqlApi racers to fail with NotFoundException or "
            f"ConcurrentModificationException, got {code}"
        )
        assert msg == _DISASSOCIATE_RACE_MESSAGES[code], f"unexpected {code} message: {msg!r}"
    gone_code, gone_msg = _poll_until(
        lambda: _association_error(svc, association_id, merged_id),
        lambda err: err[0] != "present",
        timeout_s=90, interval_s=3.0,
        description="association to disappear after the disassociation race",
    )
    assert gone_code == "NotFoundException", f"expected NotFoundException once the association is gone, got {gone_code}"
    assert gone_msg == _ASSOCIATION_NOT_FOUND, f"unexpected message: {gone_msg!r}"

    # --- merged-initiated race: concurrent AssociateSourceGraphqlApi for a fresh source against the same merged API.
    source2 = _create_graphql_api(ctx, svc)
    source2_id = source2["apiId"]
    assoc2_racers = 4

    def assoc2_attempt():
        return svc.associate_source_graphql_api(
            mergedApiIdentifier=merged_id,
            sourceApiIdentifier=source2_id,
            sourceApiAssociationConfig={"mergeType": "MANUAL_MERGE"},
        )

    results2 = _run_concurrent([assoc2_attempt for _ in range(assoc2_racers)])
    successes2 = [r for r in results2 if not isinstance(r, BaseException)]
    errors2 = _errors(results2)
    assert len(successes2) >= 1, f"expected at least one AssociateSourceGraphqlApi racer to win, got {results2!r}"
    assert len(successes2) + len(errors2) == assoc2_racers
    for code, msg in errors2:
        assert code in assoc_messages, (
            f"expected losing AssociateSourceGraphqlApi racers to fail with a state-conflict code, got {code}"
        )
        if assoc_messages[code] is not None:
            assert msg == assoc_messages[code], f"unexpected {code} message: {msg!r}"
    association_id2 = successes2[0]["sourceApiAssociation"]["associationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: svc.disassociate_source_graphql_api(mergedApiIdentifier=merged_id, associationId=association_id2)))
    listed2 = _source_association_ids(svc, merged_id, source2_id)
    assert listed2 == [association_id2], (
        f"expected the racing AssociateSourceGraphqlApi calls to leave exactly one association {association_id2!r}, listed {listed2!r}"
    )

    _poll_until(
        lambda: svc.get_source_api_association(associationId=association_id2, mergedApiIdentifier=merged_id)["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] not in ("MERGE_SCHEDULED", "MERGE_IN_PROGRESS"),
        timeout_s=90, interval_s=3.0,
        description="second merge to settle before racing DisassociateSourceGraphqlApi",
    )

    del_results2 = _run_concurrent(
        [lambda: svc.disassociate_source_graphql_api(mergedApiIdentifier=merged_id, associationId=association_id2) for _ in range(3)]
    )
    del_successes2 = _successes(del_results2)
    del_errors2 = _errors(del_results2)
    assert del_successes2 >= 1, (
        f"expected at least one DisassociateSourceGraphqlApi racer to win, got {del_results2!r}"
    )
    for code, msg in del_errors2:
        assert code in _DISASSOCIATE_RACE_MESSAGES, (
            f"expected losing DisassociateSourceGraphqlApi racers to fail with NotFoundException or "
            f"ConcurrentModificationException, got {code}"
        )
        assert msg == _DISASSOCIATE_RACE_MESSAGES[code], f"unexpected {code} message: {msg!r}"
    gone_code2, gone_msg2 = _poll_until(
        lambda: _association_error(svc, association_id2, merged_id),
        lambda err: err[0] != "present",
        timeout_s=90, interval_s=3.0,
        description="second association to disappear after the disassociation race",
    )
    assert gone_code2 == "NotFoundException", f"expected NotFoundException once the association is gone, got {gone_code2}"
    assert gone_msg2 == _ASSOCIATION_NOT_FOUND, f"unexpected message: {gone_msg2!r}"

    # --- DisassociateApi: a custom domain needs an ACM certificate AppSync accepts, which an
    # unattended test cannot obtain; exercise the referential-integrity boundary instead — concurrent
    # DisassociateApi calls against a syntactically valid but nonexistent domain must each,
    # independently, report NotFoundException.
    fake_domain = f"{ctx.unique_name('sim2real-behav-dn-')}.com"
    domain_results = _run_concurrent(
        [lambda: svc.disassociate_api(domainName=fake_domain) for _ in range(3)]
    )
    domain_errors = _errors(domain_results)
    assert len(domain_errors) == 3, "every DisassociateApi call against a nonexistent domain must fail"
    for code, msg in domain_errors:
        assert code == "NotFoundException", (
            f"expected NotFoundException for DisassociateApi on a nonexistent domain, got {code}"
        )
        assert msg == "Domain name not found.", f"unexpected message: {msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
