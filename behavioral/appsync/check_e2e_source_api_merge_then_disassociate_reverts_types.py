"""e2e-source-api-merge-then-disassociate-reverts-types."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-source-api-merge-then-disassociate-reverts-types"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating + merging a source API pulls its types into the merged API; once
    disassociated, the merged API's type list reverts to the set it had before that
    source was ever merged in."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    source_type_name = "Widget4"

    # ---- source API with a distinctive custom type ----
    source_api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-merge-src-"),
        authenticationType="API_KEY",
        tags={"sim2real-owner": "behavioral-check"},
    )["graphqlApi"]
    source_api_id = source_api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=source_api_id))
    source_sdl = (
        f"type {source_type_name} {{ id: ID! name: String }}\n"
        f"type Query {{ getWidget4(id: ID!): {source_type_name} }}\n"
        "schema { query: Query }\n"
    )
    _create_schema_and_wait(appsync, source_api_id, source_sdl, timeout_s=60)

    # ---- execution role the merged API uses to authorize SourceGraphQL calls ----
    role_name = ctx.unique_name("sim2real-appsync-merge-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    merge_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "appsync:SourceGraphQL",
                "Resource": [source_api["arn"], source_api["arn"] + "/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="source-graphql", PolicyDocument=json.dumps(merge_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="source-graphql"))

    # ---- merged API, created with no source associated yet ----
    merged_api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-merged-"),
        authenticationType="API_KEY",
        apiType="MERGED",
        mergedApiExecutionRoleArn=role_arn,
        tags={"sim2real-owner": "behavioral-check"},
    )["graphqlApi"]
    merged_api_id = merged_api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=merged_api_id))

    baseline_types = _safe_list_type_names(appsync, merged_api_id)
    assert source_type_name not in baseline_types, baseline_types

    # ---- associate + manually merge the source API in ----
    assoc = _retry_until_ready(
        lambda: appsync.associate_source_graphql_api(
            mergedApiIdentifier=merged_api_id,
            sourceApiIdentifier=source_api_id,
            sourceApiAssociationConfig={"mergeType": "MANUAL_MERGE"},
        )
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]

    # associate_source_graphql_api schedules an automatic initial merge attempt of its own; an
    # explicit StartSchemaMerge issued immediately after can race it and get rejected with
    # ConcurrentModificationException ("operation in progress"), so retry on that specific code.
    _retry_on_concurrent_modification(
        lambda: appsync.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_api_id)
    )
    _wait_association_status(
        appsync, merged_api_id, association_id, {"MERGE_SUCCESS"}, {"MERGE_FAILED"}, timeout_s=180
    )

    merged_types_after_merge = _safe_list_type_names(appsync, merged_api_id)
    assert source_type_name in merged_types_after_merge, merged_types_after_merge

    scoped_types = {
        t["name"]
        for t in appsync.list_types_by_association(
            mergedApiIdentifier=merged_api_id, associationId=association_id, format="SDL"
        )["types"]
    }
    assert source_type_name in scoped_types, scoped_types

    # ---- disassociate: the merged schema must revert to its pre-merge type set ----
    appsync.disassociate_source_graphql_api(mergedApiIdentifier=merged_api_id, associationId=association_id)
    _wait_association_gone(appsync, merged_api_id, association_id, timeout_s=180)

    reverted_types = _wait_type_removed(appsync, merged_api_id, source_type_name, timeout_s=120)
    assert source_type_name not in reverted_types, reverted_types
    assert reverted_types == baseline_types, (baseline_types, reverted_types)


def _create_schema_and_wait(appsync, api_id: str, sdl: str, timeout_s: float) -> None:
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError("schema creation failed")
        time.sleep(2)
    raise AssertionError(f"schema creation never completed within {timeout_s}s")


def _retry_until_ready(fn, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - IAM role propagation delay
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc}")


def _retry_on_concurrent_modification(fn, timeout_s: float = 30.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConcurrentModificationException":
                raise
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"operation kept racing a concurrent merge within {timeout_s}s: {last_exc}")


def _safe_list_type_names(appsync, api_id: str) -> set[str]:
    try:
        return {t["name"] for t in appsync.list_types(apiId=api_id, format="SDL")["types"]}
    except appsync.exceptions.GraphQLSchemaException:
        return set()
    except appsync.exceptions.NotFoundException:
        return set()


def _wait_association_status(appsync, merged_api_id, association_id, success_states, failure_states, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = appsync.get_source_api_association(
            mergedApiIdentifier=merged_api_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"]
        if status in success_states:
            return status
        if status in failure_states:
            detail = appsync.get_source_api_association(
                mergedApiIdentifier=merged_api_id, associationId=association_id
            )["sourceApiAssociation"].get("sourceApiAssociationStatusDetail")
            raise AssertionError(f"association reached {status}: {detail}")
        time.sleep(5)
    raise AssertionError(f"association never reached {success_states} within {timeout_s}s")


def _wait_association_gone(appsync, merged_api_id, association_id, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = appsync.get_source_api_association(
                mergedApiIdentifier=merged_api_id, associationId=association_id
            )["sourceApiAssociation"]["sourceApiAssociationStatus"]
        except appsync.exceptions.NotFoundException:
            return
        if status == "DELETION_FAILED":
            raise AssertionError("disassociation reached DELETION_FAILED")
        time.sleep(5)
    raise AssertionError(f"association {association_id} was never removed within {timeout_s}s")


def _wait_type_removed(appsync, merged_api_id: str, type_name: str, timeout_s: float) -> set[str]:
    deadline = time.monotonic() + timeout_s
    types = _safe_list_type_names(appsync, merged_api_id)
    while time.monotonic() < deadline:
        types = _safe_list_type_names(appsync, merged_api_id)
        if type_name not in types:
            return types
        time.sleep(5)
    raise AssertionError(f"type {type_name!r} was never removed from merged API types: {types}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
