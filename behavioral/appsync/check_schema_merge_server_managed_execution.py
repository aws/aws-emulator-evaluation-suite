"""schema-merge-server-managed-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-merge-server-managed-execution"
GROUP = "server-side"
SERVICES = ["appsync"]

_TERMINAL = {"MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED"}
_IN_FLIGHT = {"MERGE_SCHEDULED", "MERGE_IN_PROGRESS"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaMerge on a source-API association is executed server-side; GetSourceApiAssociation
    reflects the resulting MERGE_SUCCESS/MERGE_FAILED status without any further client-driven
    mutation of the record."""
    appsync = ctx.client("appsync")

    source = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-src-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    source_id, source_arn = source["apiId"], source["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=source_id)))

    appsync.start_schema_creation(apiId=source_id, definition=b"type Query { hello: String }")
    _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=source_id)["status"],
        lambda s: s in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=60,
        interval_s=3,
    )

    role_arn = _create_merged_api_role(ctx, source_arn)
    merged = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-merged-"),
        authenticationType="API_KEY",
        apiType="MERGED",
        mergedApiExecutionRoleArn=role_arn,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    merged_id = merged["apiId"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=merged_id)))

    assoc = _associate_with_retry(appsync, merged_id, source_id)
    association_id = assoc["associationId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: appsync.disassociate_source_graphql_api(
                mergedApiIdentifier=merged_id, associationId=association_id
            )
        )
    )
    assert assoc["sourceApiAssociationConfig"]["mergeType"] == "MANUAL_MERGE", (
        f"expected MANUAL_MERGE, got {assoc['sourceApiAssociationConfig']!r}"
    )

    first = _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] in _TERMINAL,
        timeout_s=180,
        interval_s=5,
    )
    assert first["sourceApiAssociationStatus"] in _TERMINAL, "initial merge never reached a terminal state"

    # trigger a second merge cycle explicitly; the resulting status transition is driven entirely
    # server-side by AppSync -- we only poll GetSourceApiAssociation, we never write the status.
    start_resp = appsync.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_id)
    assert start_resp["sourceApiAssociationStatus"] in (_IN_FLIGHT | _TERMINAL), start_resp

    second = _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] in _TERMINAL,
        timeout_s=180,
        interval_s=5,
    )
    assert second["sourceApiAssociationStatus"] in _TERMINAL, second
    # the server autonomously populated/refreshed the status detail as part of executing the merge
    assert "sourceApiAssociationStatusDetail" in second, (
        f"expected AppSync to populate sourceApiAssociationStatusDetail server-side, got {second!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "NotFoundException"):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _associate_with_retry(appsync, merged_id: str, source_id: str, attempts: int = 6, delay_s: float = 5.0):
    """AssociateSourceGraphqlApi is the first real use of the merge execution role's
    SourceGraphQL permission. IAM CreateRole/PutRolePolicy is eventually consistent, and AppSync
    surfaces the not-yet-assumable role as BadRequestException for a few seconds -- retry through
    that window instead of a blind pre-sleep."""
    last_exc: ClientError | None = None
    for _ in range(attempts):
        try:
            return appsync.associate_source_graphql_api(
                mergedApiIdentifier=merged_id,
                sourceApiIdentifier=source_id,
                sourceApiAssociationConfig={"mergeType": "MANUAL_MERGE"},
            )["sourceApiAssociation"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "BadRequestException":
                raise
            time.sleep(delay_s)
    assert last_exc is not None
    raise last_exc


def _create_merged_api_role(ctx, source_api_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appsync-merge-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="source-graphql")))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="source-graphql",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "appsync:SourceGraphQL",
                        "Resource": [source_api_arn, f"{source_api_arn}/*"],
                    }
                ],
            }
        ),
    )
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
