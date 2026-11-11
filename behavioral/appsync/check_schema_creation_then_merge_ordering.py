"""schema-creation-then-merge-ordering."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "schema-creation-then-merge-ordering"
GROUP = "ordering"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaMerge only reaches MERGE_SUCCESS once the source API's schema creation
    (via StartSchemaCreation) has reached SUCCESS, and GetSchemaCreationStatus itself refuses
    to report a status until a schema creation job has actually been started."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    source = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-src-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    source_id, source_arn = source["apiId"], source["arn"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=source_id))

    # A Merged API requires an IAM execution role that AppSync assumes to perform the
    # merge (appsync:SourceGraphQL against the source API); CreateGraphqlApi rejects
    # apiType=MERGED without mergedApiExecutionRoleArn.
    role_arn = _create_merge_execution_role(ctx, iam, source_arn)

    merged = _create_merged_api_with_retry(
        ctx, appsync, ctx.unique_name("sim2real-merged-"), role_arn
    )
    merged_id = merged["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=merged_id))

    # Ordering violation #1: querying schema-creation status before any StartSchemaCreation
    # call has been made for this apiId does not raise; AppSync reports the well-defined
    # "not applicable" status rather than an error, distinguishing "never started" from any
    # in-progress/terminal state.
    pre_status = appsync.get_schema_creation_status(apiId=source_id)["status"]
    assert pre_status == "NOT_APPLICABLE", (
        f"expected NOT_APPLICABLE from GetSchemaCreationStatus before any "
        f"StartSchemaCreation call, got {pre_status!r}"
    )

    association = appsync.associate_source_graphql_api(
        mergedApiIdentifier=merged_id,
        sourceApiIdentifier=source_id,
        sourceApiAssociationConfig={"mergeType": "MANUAL_MERGE"},
    )["sourceApiAssociation"]
    association_id = association["associationId"]
    ctx.on_cleanup(lambda: _teardown_association(appsync, merged_id, association_id))

    # Ordering violation #2: no merge has ever succeeded yet, so there must be no
    # lastSuccessfulMergeDate recorded on the association.
    fresh_assoc = appsync.get_source_api_association(
        associationId=association_id, mergedApiIdentifier=merged_id
    )["sourceApiAssociation"]
    fresh_merge_date = fresh_assoc.get("lastSuccessfulMergeDate")
    assert fresh_merge_date is None, (
        f"expected no lastSuccessfulMergeDate before any merge has succeeded, "
        f"got {fresh_merge_date!r}"
    )

    # Now satisfy the precondition: create a real schema on the source API and drive its
    # status through GetSchemaCreationStatus to SUCCESS.
    schema_sdl = b"type Query { hello: String }"
    appsync.start_schema_creation(apiId=source_id, definition=schema_sdl)
    creation_status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=source_id)["status"],
        lambda s: s in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=90,
        interval_s=2,
    )
    assert creation_status in ("SUCCESS", "ACTIVE"), (
        f"schema creation on source API did not reach SUCCESS/ACTIVE, got {creation_status!r}"
    )

    # Only now (schema creation SUCCESS) does StartSchemaMerge lead to MERGE_SUCCESS.
    merge_resp = appsync.start_schema_merge(
        associationId=association_id, mergedApiIdentifier=merged_id
    )
    merge_start_status = merge_resp["sourceApiAssociationStatus"]
    assert merge_start_status in ("MERGE_SCHEDULED", "MERGE_IN_PROGRESS", "MERGE_SUCCESS"), (
        f"expected StartSchemaMerge to report a merge in-flight or already done, "
        f"got {merge_start_status!r}"
    )

    final_assoc = _poll_until(
        lambda: appsync.get_source_api_association(
            associationId=association_id, mergedApiIdentifier=merged_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] in ("MERGE_SUCCESS", "MERGE_FAILED"),
        timeout_s=150,
        interval_s=3,
    )
    assert final_assoc["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"merge did not succeed after schema creation SUCCESS: "
        f"{final_assoc.get('sourceApiAssociationStatusDetail')}"
    )
    assert final_assoc.get("lastSuccessfulMergeDate") is not None, (
        "lastSuccessfulMergeDate should be set once StartSchemaMerge reaches MERGE_SUCCESS"
    )

    # Positive control: the merged API's schema now actually contains the source's field,
    # proving the merge pulled real content in (not just a status flip).
    merged_schema = appsync.get_introspection_schema(apiId=merged_id, format="SDL")["schema"].read().decode()
    assert "hello" in merged_schema, "merged API schema does not contain the source API's field"


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _create_merge_execution_role(ctx, iam: Any, source_api_arn: str) -> str:
    role_name = ctx.unique_name("sim2real-merge-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "appsync.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    policy_name = "source-graphql-access"
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["appsync:SourceGraphQL", "appsync:StartSchemaMerge"],
            "Resource": [source_api_arn, f"{source_api_arn}/*"],
        }],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy)
    )

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    # IAM roles/policies are eventually consistent; the caller's bounded retry
    # (_create_merged_api_with_retry) is what actually waits out the propagation delay.
    return role_arn


def _create_merged_api_with_retry(ctx, appsync: Any, name: str, role_arn: str) -> dict:
    from botocore.exceptions import ClientError

    def _try_create():
        try:
            return appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )["graphqlApi"]
        except ClientError as exc:
            # Freshly created IAM roles can take a short while to become assumable
            # by AppSync; retry until the role has propagated.
            if exc.response["Error"]["Code"] == "BadRequestException":
                return None
            raise

    return _poll_until(_try_create, lambda a: a is not None, timeout_s=60.0, interval_s=5.0)


def _teardown_association(appsync: Any, merged_id: str, association_id: str) -> None:
    try:
        appsync.disassociate_source_graphql_api(
            mergedApiIdentifier=merged_id, associationId=association_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            appsync.get_source_api_association(
                associationId=association_id, mergedApiIdentifier=merged_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
