"""schema-merge-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-merge-lifecycle"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaMerge on an associated (MANUAL_MERGE) source API drives GetSourceApiAssociation's
    status to MERGE_SUCCESS and republishes the updated source schema into the merged API."""
    appsync = ctx.client("appsync")

    source_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-mergesrc-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=source_id)))

    _create_schema(appsync, source_id, "type Query {\n  hello: String\n}\n")

    role_arn = _create_merge_role(ctx)
    merged_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-mergedst-"),
        authenticationType="API_KEY",
        apiType="MERGED",
        mergedApiExecutionRoleArn=role_arn,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=merged_id)))

    assoc = _associate_with_retry(
        appsync, source_id, merged_id, {"mergeType": "MANUAL_MERGE"}
    )
    association_id = assoc["associationId"]

    disassociated = {"flag": False}

    def _cleanup_assoc():
        if not disassociated["flag"]:
            _safe(
                lambda: appsync.disassociate_merged_graphql_api(
                    sourceApiIdentifier=source_id, associationId=association_id
                )
            )

    ctx.on_cleanup(_cleanup_assoc)

    status = _wait_for_association_status(
        appsync, merged_id, association_id, {"MERGE_SUCCESS", "MERGE_FAILED"}, timeout_s=180.0
    )
    if status is None:
        raise AssertionError(
            "initial association merge did not reach a terminal state within 180s",
        )
    assert status == "MERGE_SUCCESS", f"expected initial MERGE_SUCCESS, got {status}"

    baseline_query = _get_query_type(appsync, merged_id, association_id)
    assert "hello" in baseline_query["definition"], (
        f"expected 'hello' in the baseline merged schema, got: {baseline_query['definition']!r}"
    )
    assert "greeting" not in baseline_query["definition"], (
        f"expected 'greeting' absent from the baseline merged schema before the source update, "
        f"got: {baseline_query['definition']!r}"
    )

    # Evolve the source schema, then explicitly trigger a re-merge with StartSchemaMerge.
    _create_schema(appsync, source_id, "type Query {\n  hello: String\n  greeting: String\n}\n")

    merge_result = appsync.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_id)
    assert merge_result["sourceApiAssociationStatus"] in (
        "MERGE_SCHEDULED",
        "MERGE_IN_PROGRESS",
        "MERGE_SUCCESS",
    ), (
        f"expected an in-progress or terminal-success status right after StartSchemaMerge, "
        f"got {merge_result['sourceApiAssociationStatus']!r}"
    )

    status2 = _wait_for_association_status(
        appsync, merged_id, association_id, {"MERGE_SUCCESS", "MERGE_FAILED"}, timeout_s=180.0
    )
    if status2 is None:
        raise AssertionError(
            "StartSchemaMerge did not reach a terminal state within 180s",
        )
    assert status2 == "MERGE_SUCCESS", f"expected MERGE_SUCCESS after StartSchemaMerge, got {status2}"

    updated_query = _get_query_type(appsync, merged_id, association_id)
    assert "greeting" in updated_query["definition"], (
        "merged schema did not pick up the source API's new field after StartSchemaMerge"
    )

    appsync.disassociate_merged_graphql_api(sourceApiIdentifier=source_id, associationId=association_id)
    disassociated["flag"] = True

    # The disassociation is not just a status flip: it converges (asynchronously -- an
    # immediate read can still see the dying association) to gone, and once converged a
    # mutation against the dead id is rejected rather than silently accepted.
    def _removed() -> bool:
        summaries = appsync.list_source_api_associations(apiId=merged_id).get(
            "sourceApiAssociationSummaries", []
        )
        return not any(s["associationId"] == association_id for s in summaries)

    removed = _poll_until_removed(_removed, timeout_s=120.0)
    assert removed, "association should no longer be listed after DisassociateMergedGraphqlApi"

    read_code, read_message = _error(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )
    )
    assert read_code == "NotFoundException", (
        f"expected NotFoundException reading the association after disassociate, got {read_code!r}"
    )
    assert read_message == "No source API association was found", (
        f"unexpected NotFoundException message {read_message!r}"
    )
    merge_code, merge_message = _error(
        lambda: appsync.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_id)
    )
    assert merge_code == "NotFoundException", (
        f"expected NotFoundException calling StartSchemaMerge on a disassociated id, got {merge_code!r}"
    )
    assert merge_message == "No source API association was found", (
        f"unexpected NotFoundException message {merge_message!r}"
    )


def _poll_until_removed(probe, *, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        if probe():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(5.0)


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _get_query_type(appsync, merged_id, association_id):
    types = appsync.list_types_by_association(
        mergedApiIdentifier=merged_id, associationId=association_id, format="SDL"
    )["types"]
    for t in types:
        if t["name"] == "Query":
            return t
    raise AssertionError("Query type not present in merged association types")


def _create_schema(appsync, api_id, sdl):
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError("schema creation failed")
        time.sleep(3.0)
    raise AssertionError("schema creation did not complete in time")


def _create_merge_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appsync-remerge-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _associate_with_retry(appsync, source_id, merged_id, assoc_config, attempts=6):
    last_err = None
    for _ in range(attempts):
        try:
            return appsync.associate_merged_graphql_api(
                sourceApiIdentifier=source_id,
                mergedApiIdentifier=merged_id,
                sourceApiAssociationConfig=assoc_config,
            )["sourceApiAssociation"]
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("BadRequestException", "UnauthorizedException"):
                time.sleep(5.0)
                continue
            raise
    raise last_err


def _wait_for_association_status(appsync, merged_id, association_id, terminal, timeout_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"]
        if status in terminal:
            return status
        time.sleep(3.0)
    return None


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "NotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
