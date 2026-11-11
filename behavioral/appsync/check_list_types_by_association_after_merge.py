"""list-types-by-association-after-merge."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-types-by-association-after-merge"
GROUP = "state-machine"
SERVICES = ["appsync"]

_MERGE_TERMINAL = {"MERGE_SUCCESS", "MERGE_FAILED"}


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=6.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last) and time.monotonic() < deadline:
        time.sleep(interval_s)
        last = probe()
    return last


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "NotFoundException"):
            raise


def _error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _error_once_refused(fn, *, timeout_s: float, interval_s: float):
    """Retry fn() while it still SUCCEEDS (the refusal converges after the mutation that causes
    it); return the (code, message) of the first refusal. Still succeeding at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _error(fn)
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After AssociateMergedGraphqlApi completes, ListTypesByAssociation enumerates the
    merged type set from the source schema, and becomes unavailable after
    DisassociateMergedGraphqlApi removes the link."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    source_api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-lta-src-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    source_api_id, _source_api_arn = source_api["apiId"], source_api["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=source_api_id)))

    schema = b"type Query { widgetCount: Int }"
    appsync.start_schema_creation(apiId=source_api_id, definition=schema)
    schema_status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=source_api_id)["status"],
        lambda s: s != "PROCESSING",
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert schema_status in {"SUCCESS", "ACTIVE"}, f"schema creation ended in {schema_status}"

    role_name = ctx.unique_name("sim2real-appsync-lta-role-")
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
                name=ctx.unique_name("sim2real-appsync-lta-merged-"),
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

    association_id = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=source_api_id, mergedApiIdentifier=merged_api_id
    )["sourceApiAssociation"]["associationId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: appsync.disassociate_merged_graphql_api(
                sourceApiIdentifier=source_api_id, associationId=association_id
            )
        )
    )

    final = _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_api_id, associationId=association_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] in _MERGE_TERMINAL,
        timeout_s=180.0,
        interval_s=6.0,
    )
    assert final["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"expected MERGE_SUCCESS, got {final['sourceApiAssociationStatus']}: "
        f"{final.get('sourceApiAssociationStatusDetail')}"
    )

    listed = appsync.list_types_by_association(
        mergedApiIdentifier=merged_api_id, associationId=association_id, format="SDL"
    )["types"]
    names = {t["name"] for t in listed}
    assert "Query" in names, f"expected merged type set to contain Query, got {names}"
    query_type = next(t for t in listed if t["name"] == "Query")
    assert "widgetCount" in query_type["definition"], "merged Query type should carry the source field"

    appsync.disassociate_merged_graphql_api(
        sourceApiIdentifier=source_api_id, associationId=association_id
    )

    removed_code, removed_message = _error_once_refused(
        lambda: appsync.list_types_by_association(
            mergedApiIdentifier=merged_api_id, associationId=association_id, format="SDL"
        ),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert removed_code == "NotFoundException", (
        "ListTypesByAssociation should become unavailable once the source association is "
        f"removed, got error code {removed_code!r}"
    )
    assert removed_message == "No source API association was found", removed_message

    # The read is gone; a mutation against the same dead association id must fail the same
    # way, not just the read -- otherwise "gone" would only be true from one angle.
    redisassociate_code, redisassociate_message = _error(
        lambda: appsync.disassociate_merged_graphql_api(
            sourceApiIdentifier=source_api_id, associationId=association_id
        )
    )
    assert redisassociate_code == "NotFoundException", (
        "re-disassociating an already-removed association should also be NotFoundException, "
        f"got {redisassociate_code!r}"
    )
    assert redisassociate_message == "No source API association was found", redisassociate_message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
