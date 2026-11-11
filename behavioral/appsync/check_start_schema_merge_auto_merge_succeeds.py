"""start-schema-merge-auto-merge-succeeds."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-schema-merge-auto-merge-succeeds"
GROUP = "server-side"
SERVICES = ["appsync"]

_TERMINAL = {"MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED"}
_IN_FLIGHT = {"MERGE_SCHEDULED", "MERGE_IN_PROGRESS"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaMerge on an AUTO_MERGE association is accepted and drives a merge that
    GetSourceApiAssociation reflects, without changing the association's mergeType."""
    appsync = ctx.client("appsync")

    source = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-src-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    source_id, source_arn = source["apiId"], source["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=source_id)))

    role_arn = _create_merged_api_role(ctx, source_arn)
    merged = _poll_until(
        lambda: _try_create_merged_api(appsync, ctx, role_arn),
        lambda a: a is not None,
        timeout_s=60,
        interval_s=5,
    )
    merged_id = merged["apiId"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=merged_id)))

    assoc = appsync.associate_source_graphql_api(
        mergedApiIdentifier=merged_id,
        sourceApiIdentifier=source_id,
        sourceApiAssociationConfig={"mergeType": "AUTO_MERGE"},
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: appsync.disassociate_source_graphql_api(
                mergedApiIdentifier=merged_id, associationId=association_id
            )
        )
    )
    assert assoc["sourceApiAssociationConfig"]["mergeType"] == "AUTO_MERGE"

    # let the automatic initial merge finish so the second, manual merge we trigger below is
    # unambiguous and not a spurious ConcurrentModificationException from an in-flight auto merge.
    _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"],
        lambda s: s in _TERMINAL,
        timeout_s=180,
        interval_s=5,
    )

    # StartSchemaMerge is accepted for an AUTO_MERGE association -- it is not gated to
    # MANUAL_MERGE-only associations. Confirm it succeeds (no BadRequestException) and drives
    # a real merge that GetSourceApiAssociation reflects.
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
    # a manually-triggered merge must not silently flip the association's configured merge type
    assert second["sourceApiAssociationConfig"]["mergeType"] == "AUTO_MERGE"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "NotFoundException"):
            raise


def _error_code(fn):
    try:
        fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        return getattr(exc, "response", {}).get("Error", {}).get("Code")
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _try_create_merged_api(appsync, ctx, role_arn: str):
    from botocore.exceptions import ClientError

    try:
        return appsync.create_graphql_api(
            name=ctx.unique_name("sim2real-appsync-merged-"),
            authenticationType="API_KEY",
            apiType="MERGED",
            mergedApiExecutionRoleArn=role_arn,
            tags={"sim2real": CHECK, "sim2real:managed": "true"},
        )["graphqlApi"]
    except ClientError as exc:
        # Freshly created IAM roles can take a short while to become assumable by
        # AppSync; retry until the role has propagated.
        if exc.response["Error"]["Code"] == "BadRequestException":
            return None
        raise


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
