"""start-schema-merge-concurrent-modification."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-schema-merge-concurrent-modification"
GROUP = "concurrency"
SERVICES = ["appsync"]

_SCHEMA = b"schema { query: Query }\ntype Query { hello: String }\n"

#: Seconds the check's teardowns may spend retrying a refusal while a merge is still running.
_CLEANUP_BUDGET_S = 900.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing StartSchemaMerge calls on one source-API association either succeed or fail
    ConcurrentModificationException, never another error, and the association settles in
    one terminal merge status."""
    appsync = ctx.client("appsync")

    source_id = _create_graphql_api(ctx, apiType="GRAPHQL")
    # A Merged API requires an execution role that AppSync assumes to merge
    # schemas from its source APIs; CreateGraphqlApi rejects apiType=MERGED
    # without mergedApiExecutionRoleArn ("Merged API execution role must be
    # specified for a Merged API"). Note the parameter is
    # "mergedApiExecutionRoleArn" (not "...RoleId") -- botocore's appsync
    # model has no "mergedApiExecutionRoleId" field and rejects it with
    # ParamValidationError("Unknown parameter in input").
    merged_role_arn = _create_merged_api_execution_role(ctx)
    merged_id = _create_graphql_api(
        ctx, apiType="MERGED", mergedApiExecutionRoleArn=merged_role_arn
    )

    # Give the source API a minimal schema so the association has something
    # real to merge.
    appsync.start_schema_creation(apiId=source_id, definition=_SCHEMA)
    _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=source_id)["status"],
        lambda s: s in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=45.0,
        interval_s=2.0,
    )

    assoc = appsync.associate_source_graphql_api(
        mergedApiIdentifier=merged_id,
        sourceApiIdentifier=source_id,
        sourceApiAssociationConfig={"mergeType": "MANUAL_MERGE"},
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(appsync, merged_id, association_id))

    # AssociateSourceGraphqlApi itself kicks off an initial merge. If that
    # merge is still in flight when we fire our racers, *every* racer
    # collides with it (not just with each other), and none of them would
    # succeed -- which would falsely look like the "serialize concurrent
    # merges" invariant was violated in the other direction (zero winners).
    # Wait for that initial merge to settle into a terminal status first, so
    # our race starts from a clean slate and is guaranteed exactly one
    # winner among the racers themselves.
    _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"],
        lambda s: s not in ("MERGE_SCHEDULED", "MERGE_IN_PROGRESS"),
        timeout_s=90.0,
        interval_s=3.0,
    )

    # Fire the merges immediately -- now that no merge is in flight, this
    # maximizes the chance our own racers overlap with each other in time.
    racer_count = 6

    def _merge(_i: int):
        try:
            resp = appsync.start_schema_merge(
                associationId=association_id, mergedApiIdentifier=merged_id
            )
            return ("ok", resp["sourceApiAssociationStatus"], None)
        except Exception as err:  # noqa: BLE001 - classify below
            return ("error", None, _code_of(err))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_merge, i) for i in range(racer_count)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]
    bad_error_codes = sorted({code for (_, _, code) in errors if code != "ConcurrentModificationException"})

    assert not bad_error_codes, (
        f"racing StartSchemaMerge calls raised non-ConcurrentModificationException errors: {bad_error_codes}"
    )
    assert successes, f"expected at least one racing StartSchemaMerge to succeed, got {results}"
    valid_statuses = {
        "MERGE_SCHEDULED",
        "MERGE_IN_PROGRESS",
        "MERGE_SUCCESS",
        "MERGE_FAILED",
        "AUTO_MERGE_SCHEDULE_FAILED",
    }
    for _, status, _ in successes:
        assert status in valid_statuses, f"unexpected sourceApiAssociationStatus: {status!r}"

    # The racers' own responses are not the verdict -- confirm the effect at the
    # association resource itself, through an independent read (GetSourceApiAssociation,
    # not StartSchemaMerge), and require it to actually settle rather than stay in flight.
    final_association = _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] not in ("MERGE_SCHEDULED", "MERGE_IN_PROGRESS"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    final_status = final_association["sourceApiAssociationStatus"]
    assert final_status in ("MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED"), (
        f"association did not settle into a terminal status after the race, got {final_status!r}"
    )


def _create_graphql_api(ctx, apiType: str, **extra) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name(f"sim2real-behav-{apiType.lower()}-")

    # A freshly-created IAM role is not always immediately usable by AppSync
    # (IAM changes propagate asynchronously), so retry briefly on the
    # specific "role could not be assumed"/invalid-role errors rather than
    # treating them as a hard failure.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            resp = appsync.create_graphql_api(
                name=name, authenticationType="API_KEY", apiType=apiType, **extra
            )
            break
        except Exception as err:  # noqa: BLE001
            code = _code_of(err)
            message = str(err)
            role_not_ready = (
                extra.get("mergedApiExecutionRoleArn")
                and code in ("BadRequestException", "AccessDeniedException")
                and ("role" in message.lower() or "assume" in message.lower())
            )
            if role_not_ready and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise

    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _create_merged_api_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-mergedapi-role-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "appsync.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["appsync:SourceGraphQL", "appsync:StartSchemaMerge"],
                "Resource": "*",
            }
        ],
    }

    try:
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
        )["Role"]["Arn"]
    except Exception as err:  # noqa: BLE001
        raise AssertionError(f"could not create IAM role for merged API execution: {err}")
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return role_arn


def _disassociate_and_wait(appsync, merged_id: str, association_id: str) -> None:
    """Disassociate the source API, retrying ConcurrentModificationException every 2 s while a
    racing merge still runs, then wait for the association to be gone; raise on anything else."""
    deadline = time.monotonic() + _CLEANUP_BUDGET_S
    while True:
        try:
            appsync.disassociate_source_graphql_api(
                mergedApiIdentifier=merged_id, associationId=association_id
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                break
            if code != "ConcurrentModificationException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)

    def _probe():
        return _error_code(
            lambda: appsync.get_source_api_association(
                mergedApiIdentifier=merged_id, associationId=association_id
            )
        )

    _poll_until(_probe, lambda c: c == "NotFoundException", timeout_s=60.0, interval_s=2.0)


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return None


def _code_of(err) -> str:
    from botocore.exceptions import ClientError

    if isinstance(err, ClientError):
        return err.response["Error"]["Code"]
    return type(err).__name__


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
