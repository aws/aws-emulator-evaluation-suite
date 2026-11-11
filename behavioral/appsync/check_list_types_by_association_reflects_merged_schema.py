"""list-types-by-association-reflects-merged-schema."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-types-by-association-reflects-merged-schema"
GROUP = "server-side"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTypesByAssociation returns only that source API's types, matching the source's ListTypes,
    while the Merged API's own ListTypes returns the types of all associated sources.
    """
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    source1_id = _create_source_api(ctx, appsync, "src1", "type Query { ping1: String }\ntype Widget { id: ID! name: String }")
    source2_id = _create_source_api(ctx, appsync, "src2", "type Query { ping2: String }\ntype Gadget { id: ID! label: String }")
    merged_id = _create_merged_api(ctx, appsync, iam)

    assoc1 = _associate_and_wait(ctx, appsync, source1_id, merged_id)
    assoc2 = _associate_and_wait(ctx, appsync, source2_id, merged_id)
    assert assoc1["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"expected src1 association to reach MERGE_SUCCESS, got "
        f"{assoc1['sourceApiAssociationStatus']!r}: {assoc1.get('sourceApiAssociationStatusDetail')}"
    )
    assert assoc2["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"expected src2 association to reach MERGE_SUCCESS, got "
        f"{assoc2['sourceApiAssociationStatus']!r}: {assoc2.get('sourceApiAssociationStatusDetail')}"
    )

    assoc1_id = assoc1["associationId"]
    assoc2_id = assoc2["associationId"]

    assoc1_types = _type_names(
        appsync.list_types_by_association(
            mergedApiIdentifier=merged_id, associationId=assoc1_id, format="SDL"
        )["types"]
    )
    assoc2_types = _type_names(
        appsync.list_types_by_association(
            mergedApiIdentifier=merged_id, associationId=assoc2_id, format="SDL"
        )["types"]
    )

    # Each association's scoped view exposes exactly its own source's contributed type,
    # and not the sibling source's type.
    assert "Widget" in assoc1_types and "Gadget" not in assoc1_types, assoc1_types
    assert "Gadget" in assoc2_types and "Widget" not in assoc2_types, assoc2_types

    # The owning Merged API's own ListTypes reflects the full composed schema: both
    # source-contributed types are present simultaneously.
    merged_types = _type_names(appsync.list_types(apiId=merged_id, format="SDL")["types"])
    assert "Widget" in merged_types and "Gadget" in merged_types, merged_types

    # And the source APIs' own standalone ListTypes views match what their association
    # scope reports (the association view mirrors the source, not the merged output).
    source1_types = _type_names(appsync.list_types(apiId=source1_id, format="SDL")["types"])
    source2_types = _type_names(appsync.list_types(apiId=source2_id, format="SDL")["types"])
    assert assoc1_types == source1_types, (assoc1_types, source1_types)
    assert assoc2_types == source2_types, (assoc2_types, source2_types)


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


def _create_source_api(ctx, appsync, tag: str, extra_sdl: str) -> str:
    name = ctx.unique_name(f"sim2real-appsync-{tag}-")
    api = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    definition = ("schema { query: Query }\n" + extra_sdl).encode("utf-8")
    appsync.start_schema_creation(apiId=api_id, definition=definition)
    status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id)["status"],
        lambda s: s in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert status in ("SUCCESS", "ACTIVE"), f"schema creation failed for {tag}: {status}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
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
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
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
