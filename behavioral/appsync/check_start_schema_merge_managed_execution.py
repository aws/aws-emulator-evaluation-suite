"""start-schema-merge-managed-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-schema-merge-managed-execution"
GROUP = "server-side"
SERVICES = ["appsync"]

_SOURCE_SCHEMA = "type Query {\n  hello: String\n}\n"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaMerge on an existing source-API association reaches MERGE_SUCCESS through
    AppSync's own asynchronous merge, and the merged API's schema gains the source API's field."""
    appsync = ctx.client("appsync")

    source_api_id, source_api_arn = _create_source_api(ctx)
    merged_role_arn = _create_merge_execution_role(ctx, source_api_arn)
    merged_api_id = _create_merged_api(ctx, merged_role_arn)

    association = _associate_source_with_retry(ctx, merged_api_id, source_api_id)
    association_id = association["associationId"]
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: appsync.disassociate_source_graphql_api(
                mergedApiIdentifier=merged_api_id, associationId=association_id
            )
        )
    )

    initial_status = _poll_association_status(
        ctx, merged_api_id, association_id, {"MERGE_SUCCESS", "MERGE_FAILED"}, timeout_s=180
    )
    assert initial_status == "MERGE_SUCCESS", f"initial merge did not succeed: {initial_status}"

    # Trigger an explicit, second merge. From here we only observe the status field
    # AppSync reports -- there is no client-side merge algorithm to run.
    appsync.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_api_id)
    final_status = _poll_association_status(
        ctx, merged_api_id, association_id, {"MERGE_SUCCESS", "MERGE_FAILED"}, timeout_s=180
    )
    assert final_status == "MERGE_SUCCESS", f"explicit StartSchemaMerge did not succeed: {final_status}"

    # the merged API's schema now really contains the source API's field.
    merged_type = appsync.get_type(apiId=merged_api_id, typeName="Query", format="SDL")["type"]
    assert "hello" in merged_type["definition"], (
        f"merged schema should contain the source field 'hello', got: {merged_type['definition']!r}"
    )


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "NotFoundException"):
            raise


def _poll_schema_status(ctx, api_id: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    appsync = ctx.client("appsync")
    terminal = {"SUCCESS", "ACTIVE", "FAILED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"schema creation for {api_id} timed out (last status={status})")


def _create_source_api(ctx):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-src-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    api_arn = resp["graphqlApi"]["arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: appsync.delete_graphql_api(apiId=api_id)))

    appsync.start_schema_creation(apiId=api_id, definition=_SOURCE_SCHEMA.encode("utf-8"))
    status = _poll_schema_status(ctx, api_id)
    assert status in {"SUCCESS", "ACTIVE"}, f"source schema creation failed: {status}"
    return api_id, api_arn


def _create_merge_execution_role(ctx, source_api_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mergerole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "sim2real-merge-access"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["appsync:SourceGraphQL"],
                "Resource": [source_api_arn, f"{source_api_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(
        lambda: _safe_call(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    return role_arn


def _create_merged_api(ctx, role_arn: str) -> str:
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-merged-"),
        authenticationType="API_KEY",
        apiType="MERGED",
        mergedApiExecutionRoleArn=role_arn,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: appsync.delete_graphql_api(apiId=api_id)))
    return api_id


def _associate_source_with_retry(ctx, merged_api_id: str, source_api_id: str, attempts: int = 6, delay_s: float = 5.0):
    """Retries on BadRequestException: the merge execution role can take a few
    seconds to become assumable after IAM CreateRole/PutRolePolicy (eventual
    consistency), which AppSync surfaces as a BadRequestException here."""
    appsync = ctx.client("appsync")
    last_exc: ClientError | None = None
    for _ in range(attempts):
        try:
            resp = appsync.associate_source_graphql_api(
                mergedApiIdentifier=merged_api_id, sourceApiIdentifier=source_api_id
            )
            return resp["sourceApiAssociation"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "BadRequestException":
                raise
            time.sleep(delay_s)
    assert last_exc is not None
    raise last_exc


def _poll_association_status(ctx, merged_api_id: str, association_id: str, terminal_statuses: set, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    appsync = ctx.client("appsync")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_source_api_association(
            mergedApiIdentifier=merged_api_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"association {association_id} did not reach terminal status in {timeout_s}s (last={status})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
