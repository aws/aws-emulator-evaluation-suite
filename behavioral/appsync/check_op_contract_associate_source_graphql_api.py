"""op-contract-associateSourceGraphqlApi."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-associateSourceGraphqlApi"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateSourceGraphqlApi links a source API to a merged API (MERGE_SCHEDULED),
    and rejects a sourceApiIdentifier that does not exist with BadRequestException."""
    appsync = ctx.client("appsync")

    source = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-source-"),
        authenticationType="API_KEY",
        apiType="GRAPHQL",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    source_id, source_arn = source["apiId"], source["arn"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=source_id))

    # NOTE: verified against real AWS, CreateGraphqlApi for a MERGED api now requires
    # mergedApiExecutionRoleArn ("Merged API execution role must be specified for a Merged
    # API"). Provision a role AppSync can assume to source-query the source API.
    role_arn = _create_merge_execution_role(ctx, source_arn)

    merged = _create_merged_api_with_retry(
        ctx, appsync, ctx.unique_name("sim2real-behav-merged-"), role_arn
    )["graphqlApi"]
    merged_id = merged["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=merged_id))

    # --- positive control: valid merged + valid source succeeds ---
    resp = appsync.associate_source_graphql_api(
        mergedApiIdentifier=merged_id,
        sourceApiIdentifier=source_id,
        description="sim2real behavioral association",
    )["sourceApiAssociation"]
    association_id = resp["associationId"]
    assert resp["sourceApiId"] == source_id, f"expected sourceApiId={source_id}, got {resp['sourceApiId']}"
    assert resp["mergedApiId"] == merged_id, f"expected mergedApiId={merged_id}, got {resp['mergedApiId']}"
    assert resp["sourceApiAssociationStatus"] in (
        "MERGE_SCHEDULED",
        "MERGE_IN_PROGRESS",
        "MERGE_SUCCESS",
        "AUTO_MERGE_SCHEDULE_FAILED",
    ), f"unexpected sourceApiAssociationStatus: {resp['sourceApiAssociationStatus']}"

    def _cleanup_association():
        from botocore.exceptions import ClientError

        try:
            appsync.disassociate_source_graphql_api(
                mergedApiIdentifier=merged_id, associationId=association_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        # DisassociateSourceGraphqlApi is async (DELETION_SCHEDULED -> gone); deleting the
        # merged API before removal lands leaves it stuck, so wait it out here rather than
        # in the merged-API delete cleanup that runs right after this one.
        deadline = time.monotonic() + 50.0
        while time.monotonic() < deadline:
            try:
                appsync.get_source_api_association(
                    mergedApiIdentifier=merged_id, associationId=association_id
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NotFoundException":
                    return
                raise
            time.sleep(2)
        raise TimeoutError(f"association {association_id} still present 50s after DisassociateSourceGraphqlApi")

    ctx.on_cleanup(_cleanup_association)

    # confirm the association is actually observable via GetSourceApiAssociation
    fetched = appsync.get_source_api_association(
        mergedApiIdentifier=merged_id, associationId=association_id
    )["sourceApiAssociation"]
    assert fetched["associationId"] == association_id, (
        f"expected associationId={association_id}, got {fetched['associationId']}"
    )
    assert fetched["sourceApiId"] == source_id, f"expected sourceApiId={source_id}, got {fetched['sourceApiId']}"

    # --- broken precondition: sourceApiIdentifier does not exist ---
    # NOTE: verified against real AWS, both an arbitrary/malformed string (e.g.
    # "does-not-exist-<ts>") *and* a well-formed-but-never-issued apiId (same shape as
    # a real apiId, e.g. a real apiId with its last character flipped) are rejected by
    # AssociateSourceGraphqlApi as BadRequestException, not NotFoundException. Unlike a
    # simple lookup-by-id operation, associate resolves/validates the source identifier
    # as part of request validation before attempting to locate the resource, so an
    # unresolvable sourceApiIdentifier surfaces as a bad request rather than a 404.
    bogus_source_id = source_id[:-1] + ("0" if source_id[-1] != "0" else "1")
    code, message = _error(
        lambda: appsync.associate_source_graphql_api(
            mergedApiIdentifier=merged_id,
            sourceApiIdentifier=bogus_source_id,
            description="should fail",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == f"Invalid API ID {bogus_source_id}", (
        f"expected AWS's exact invalid-source message naming {bogus_source_id!r}, got {message!r}"
    )

    # the forbidden association must not exist: the merged API's only association is still
    # the original (valid) one -- no phantom association was created for the bogus source.
    assocs = appsync.list_source_api_associations(apiId=merged_id)["sourceApiAssociationSummaries"]
    assert len(assocs) == 1, f"expected exactly 1 association on {merged_id}, got {len(assocs)}: {assocs}"
    assert assocs[0]["associationId"] == association_id, (
        f"expected the surviving association to be {association_id}, got {assocs[0]['associationId']}"
    )


# ===== helpers =====
def _error(fn) -> Any:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because a
    target that accepts a call real AWS refuses must not pass that acceptance off as a
    plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_merge_execution_role(ctx, source_api_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-merge-role-")
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    policy_name = "source-graphql-access"
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["appsync:SourceGraphQL"],
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
    return role_arn


def _create_merged_api_with_retry(ctx, appsync, name: str, role_arn: str):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )
        except ClientError as exc:
            last_exc = exc
            # IAM role propagation lag: AppSync validates it can assume the role at
            # creation time and returns BadRequestException until the role is visible.
            if exc.response["Error"]["Code"] == "BadRequestException":
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create merged API after role propagation wait: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
