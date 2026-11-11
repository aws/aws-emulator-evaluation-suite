"""merged-api-wrong-target-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "merged-api-wrong-target-type-rejected"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateMergedGraphqlApi rejects a mergedApiIdentifier that does not reference an
    apiType=MERGED GraphQL API (BadRequestException) and creates no association record;
    pointing it at a real MERGED API is accepted and produces a source association."""
    appsync = ctx.client("appsync")

    source_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-src-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_graphql_api(apiId=source_id)))

    not_merged_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-plain-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_graphql_api(apiId=not_merged_id)))

    # Negative: mergedApiIdentifier refers to a standard (apiType=GRAPHQL) API, not a MERGED one.
    code, message = _error(
        lambda: appsync.associate_merged_graphql_api(
            sourceApiIdentifier=source_id, mergedApiIdentifier=not_merged_id
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == f"Invalid API type, expected api to be type MERGED for api : {not_merged_id}", message

    leaked = appsync.list_source_api_associations(apiId=source_id).get("sourceApiAssociationSummaries", [])
    assert leaked == [], "a rejected AssociateMergedGraphqlApi call must not create an association record"

    # Positive control: a real apiType=MERGED target is accepted. CreateGraphqlApi requires a
    # mergedApiExecutionRoleArn for apiType=MERGED (the role AppSync assumes to pull the source
    # APIs' schemas when performing the merge) — mint a minimal one.
    merged_role_arn = _create_merged_api_execution_role(ctx)
    merged_id = _create_merged_graphql_api_with_retry(
        appsync, ctx.unique_name("sim2real-behav-merged-"), merged_role_arn, tags=CHECK
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_graphql_api(apiId=merged_id)))

    control = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=source_id, mergedApiIdentifier=merged_id
    )["sourceApiAssociation"]
    association_id = control["associationId"]
    assert control["sourceApiId"] == source_id, f"expected sourceApiId {source_id!r}, got {control['sourceApiId']!r}"
    assert control["mergedApiId"] == merged_id, f"expected mergedApiId {merged_id!r}, got {control['mergedApiId']!r}"
    status = control["sourceApiAssociationStatus"]
    assert status in ("MERGE_SCHEDULED", "MERGE_IN_PROGRESS", "MERGE_SUCCESS"), (
        f"expected an in-flight or completed merge status, got {status!r}"
    )
    ctx.on_cleanup(lambda: _safe_disassociate(appsync, source_id, association_id))

    accepted = appsync.list_source_api_associations(apiId=source_id).get("sourceApiAssociationSummaries", [])
    assert any(a["associationId"] == association_id for a in accepted), (
        f"expected association {association_id!r} in {accepted!r}"
    )


def _error(fn):
    """Call fn(); return its error code. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_merged_api_execution_role(ctx) -> str:
    """A merged API's CreateGraphqlApi call requires mergedApiExecutionRoleArn — the role
    AppSync assumes to read the source APIs' schemas during a merge. Trust policy grants
    appsync.amazonaws.com sts:AssumeRole; the permissions policy grants the documented
    appsync:SourceGraphQLAPI action the merge needs."""
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-merged-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "sim2real-behav-merged-policy"
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "appsync:SourceGraphQLAPI", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy)
    )
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    )
    return role_arn


def _create_merged_graphql_api_with_retry(
    appsync, name: str, role_arn: str, tags: str, timeout_s: float = 60.0
) -> str:
    """A freshly-created IAM role isn't always immediately visible to AppSync (eventual
    consistency), so CreateGraphqlApi(apiType=MERGED) can transiently reject a just-minted
    mergedApiExecutionRoleArn; retry for a bounded window rather than failing on that race."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": tags, "sim2real:managed": "true"},
            )["graphqlApi"]["apiId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code == "BadRequestException" and "role" in message and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _safe_disassociate(appsync, source_api_id: str, association_id: str) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            appsync.disassociate_merged_graphql_api(
                sourceApiIdentifier=source_api_id, associationId=association_id
            )
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "ConcurrentModificationException":
                time.sleep(10)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
