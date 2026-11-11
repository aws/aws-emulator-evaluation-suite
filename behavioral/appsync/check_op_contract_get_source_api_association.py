"""op-contract-getSourceApiAssociation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getSourceApiAssociation"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSourceApiAssociation returns the exact source/merged apiId pairing for a real
    association; an unknown associationId on the same merged API is rejected with NotFoundException."""
    appsync = ctx.client("appsync")
    merged_id = _create_merged_graphql_api(ctx)
    source_id = _create_graphql_api(ctx, api_type="GRAPHQL")

    assoc = appsync.associate_source_graphql_api(
        mergedApiIdentifier=merged_id, sourceApiIdentifier=source_id
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: appsync.disassociate_source_graphql_api(
                mergedApiIdentifier=merged_id, associationId=association_id
            )
        )
    )

    got = appsync.get_source_api_association(
        mergedApiIdentifier=merged_id, associationId=association_id
    )["sourceApiAssociation"]
    assert got["associationId"] == association_id, (
        f"expected associationId {association_id}, got {got['associationId']}"
    )
    assert got["sourceApiId"] == source_id, (
        f"expected sourceApiId {source_id}, got {got['sourceApiId']}"
    )
    assert got["mergedApiId"] == merged_id, (
        f"expected mergedApiId {merged_id}, got {got['mergedApiId']}"
    )
    assert got["associationArn"] == assoc["associationArn"], (
        f"expected associationArn {assoc['associationArn']}, got {got['associationArn']}"
    )

    code, message = _error(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId="00000000-0000-0000-0000-000000000000"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "No source API association was found", message


# ===== helpers =====
def _create_graphql_api(ctx, api_type: str) -> str:
    appsync = ctx.client("appsync")
    kwargs = {
        "name": ctx.unique_name("sim2real-gql-"),
        "authenticationType": "API_KEY",
        "tags": {"sim2real": CHECK, "sim2real:managed": "true"},
    }
    if api_type != "GRAPHQL":
        kwargs["apiType"] = api_type
    api_id = appsync.create_graphql_api(**kwargs)["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _delete_source_api_once_detached(appsync, api_id))
    return api_id


def _create_merged_graphql_api(ctx) -> str:
    """A MERGED API requires an execution role (mergedApiExecutionRoleArn); create one."""
    appsync = ctx.client("appsync")
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
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="SourceGraphQLAccess",
        PolicyDocument=json.dumps(
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
        ),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="SourceGraphQLAccess"))
    )

    # A freshly-created IAM role is not immediately assumable everywhere (IAM's eventual
    # consistency window), so CreateGraphqlApi for a MERGED api can transiently reject the
    # still-propagating role with BadRequestException; retry within a bounded window.
    merged_api_id = None
    deadline = time.monotonic() + 30.0
    last_err = None
    while merged_api_id is None and time.monotonic() < deadline:
        try:
            merged_api_id = appsync.create_graphql_api(
                name=ctx.unique_name("sim2real-appsync-merged-"),
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )["graphqlApi"]["apiId"]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] != "BadRequestException":
                raise
            time.sleep(3.0)
    if merged_api_id is None:
        raise AssertionError(f"could not create merged API: {last_err}")
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=merged_api_id)))
    return merged_api_id


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "NotFoundException"):
            raise


def _delete_source_api_once_detached(appsync, api_id: str) -> None:
    """DisassociateSourceGraphqlApi's own response is synchronous, but the source API's
    internal "associated to a Merged API" flag clears a moment later; DeleteGraphqlApi called
    immediately after disassociate can still see the stale flag and reject with
    BadRequestException. Retry within a bounded window instead of swallowing the failure."""
    deadline = time.monotonic() + 50.0
    while True:
        try:
            appsync.delete_graphql_api(apiId=api_id)
            return
        except ClientError as exc:
            still_associated = (
                exc.response["Error"]["Code"] == "BadRequestException"
                and "associated" in exc.response["Error"].get("Message", "").lower()
            )
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            if not still_associated or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _error(fn):
    """Call fn(); return its error code. An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses must not pass as a mere
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
