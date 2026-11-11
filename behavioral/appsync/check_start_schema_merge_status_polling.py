"""start-schema-merge-status-polling."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-schema-merge-status-polling"
GROUP = "server-side"
SERVICES = ["appsync"]

_INITIAL_SCHEMA = b"""
schema { query: Query }
type Query { ping: String }
"""

_EXTRA_TYPE_SDL = "type ExtraType { id: ID! }"
_QUERY_WITH_EXTRA_SDL = "type Query { ping: String extra: ExtraType }"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A source schema change reaches the Merged API only after StartSchemaMerge: polling
    GetSourceApiAssociation to MERGE_SUCCESS, the new type then appears in the merged ListTypes.
    """
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    source_id = _create_and_activate_source_api(ctx, appsync)
    merged_id = _create_merged_api(ctx, appsync, iam)
    association = _associate_and_wait(ctx, appsync, source_id, merged_id)
    association_id = association["associationId"]

    assert association["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"expected initial merge to succeed, got {association['sourceApiAssociationStatus']}"
    )

    # Baseline: the merged API's own composed schema does not yet know about ExtraType.
    baseline_names = _type_names(appsync.list_types(apiId=merged_id, format="SDL")["types"])
    assert "ExtraType" not in baseline_names, f"expected no ExtraType before any mutation, got {baseline_names}"

    first_merge_date = association.get("lastSuccessfulMergeDate")
    assert first_merge_date is not None, "expected lastSuccessfulMergeDate to be set after the initial merge"

    # Mutate the *source* API's schema: add a new object type and wire it onto Query.
    appsync.create_type(apiId=source_id, format="SDL", definition=_EXTRA_TYPE_SDL)
    appsync.update_type(apiId=source_id, typeName="Query", format="SDL", definition=_QUERY_WITH_EXTRA_SDL)

    # The change does NOT propagate to the merged API until an explicit re-merge.
    still_baseline = _type_names(appsync.list_types(apiId=merged_id, format="SDL")["types"])
    assert "ExtraType" not in still_baseline, (
        f"expected the source mutation to NOT auto-propagate before an explicit re-merge, got {still_baseline}"
    )

    appsync.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_id)

    final_association = _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] in ("MERGE_SUCCESS", "MERGE_FAILED"),
        timeout_s=180.0,
        interval_s=4.0,
    )
    assert final_association["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"re-merge did not succeed: {final_association.get('sourceApiAssociationStatusDetail')}"
    )
    second_merge_date = final_association.get("lastSuccessfulMergeDate")
    assert second_merge_date is not None and second_merge_date >= first_merge_date, (
        "lastSuccessfulMergeDate did not advance after an explicit StartSchemaMerge"
    )

    # Now the merged API's own composed schema reflects the source API's new type.
    merged_names = _type_names(appsync.list_types(apiId=merged_id, format="SDL")["types"])
    assert "ExtraType" in merged_names, f"merged schema did not pick up the re-merged type: {merged_names}"


def _type_names(types: list[dict[str, Any]]) -> set[str]:
    return {t["name"] for t in types}


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 120.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_and_activate_source_api(ctx, appsync) -> str:
    name = ctx.unique_name("sim2real-appsync-src-")
    api = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real-check": CHECK}
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    appsync.start_schema_creation(apiId=api_id, definition=_INITIAL_SCHEMA)
    status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id)["status"],
        lambda s: s in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert status in ("SUCCESS", "ACTIVE"), f"source API schema creation failed: {status}"
    return api_id


def _create_merged_api(ctx, appsync, iam) -> str:
    from botocore.exceptions import ClientError

    role_arn = _create_merge_execution_role(ctx, iam)
    name = ctx.unique_name("sim2real-appsync-merged-")

    def _try_create():
        try:
            return appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real-check": CHECK},
            )["graphqlApi"]
        except ClientError as exc:
            # Freshly created IAM roles can take a short while to become assumable
            # by AppSync; retry until the role has propagated.
            if exc.response["Error"]["Code"] == "BadRequestException":
                return None
            raise

    api = _poll_until(_try_create, lambda a: a is not None, timeout_s=60.0, interval_s=5.0)
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _create_merge_execution_role(ctx, iam) -> str:
    """Create the role AppSync assumes to merge sources; CreateGraphqlApi rejects apiType=MERGED
    without mergedApiExecutionRoleArn."""
    role_name = ctx.unique_name("sim2real-appsync-merge-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "appsync.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    policy_name = f"{role_name}-policy"
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["appsync:SourceGraphQL", "appsync:StartSchemaMerge"],
                    "Resource": "*",
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_document)
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, policy_name))
    return role_arn


def _delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(iam, role_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _associate_and_wait(ctx, appsync, source_id: str, merged_id: str) -> dict[str, Any]:
    created = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=source_id, mergedApiIdentifier=merged_id
    )["sourceApiAssociation"]
    association_id = created["associationId"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(appsync, source_id, merged_id, association_id))

    return _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] in ("MERGE_SUCCESS", "MERGE_FAILED"),
        timeout_s=180.0,
        interval_s=4.0,
    )


def _disassociate_and_wait(appsync, source_id: str, merged_id: str, association_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appsync.disassociate_merged_graphql_api(sourceApiIdentifier=source_id, associationId=association_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            appsync.get_source_api_association(mergedApiIdentifier=merged_id, associationId=association_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(2.0)
    raise TimeoutError(f"source API association {association_id} still present 90s after DisassociateMergedGraphqlApi")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
