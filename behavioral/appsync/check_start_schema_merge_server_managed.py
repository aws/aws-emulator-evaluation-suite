"""start-schema-merge-server-managed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _association_gone(svc, association_id, merged_id):
    """True once GetSourceApiAssociation reports NotFoundException, False while it still reads."""
    try:
        svc.get_source_api_association(associationId=association_id, mergedApiIdentifier=merged_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return True
        raise
    return False

def _retry_on_role_not_yet_assumable(fn, *, timeout_s=60, interval_s=3.0):
    """CreateGraphqlApi(apiType=MERGED) validates the execution role's trust policy at call
    time; a role created moments earlier can still read as not-yet-assumable due to IAM's own
    eventual consistency. Retry the bounded window instead of sleeping blind before the call."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "BadRequestException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _poll_until(probe, predicate, *, timeout_s=90, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "start-schema-merge-server-managed"
GROUP = 'source-api-association'
SERVICES = ['appsync']

def _create_merged_api(ctx, svc):
    """Create a MERGED-type GraphQL API with a throwaway execution role (required by AppSync for
    apiType=MERGED even under MANUAL_MERGE)."""
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-behav-merged-api-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-merged-api-access",
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
    merged = _retry_on_role_not_yet_assumable(
        lambda: svc.create_graphql_api(
            name=ctx.unique_name("sim2real-behav-merged-"),
            apiType="MERGED",
            authenticationType="API_KEY",
            mergedApiExecutionRoleArn=role["Arn"],
            tags={"sim2real": CHECK, "sim2real:managed": "true"},
        )["graphqlApi"]
    )
    ctx.on_cleanup(lambda _a=merged: svc.delete_graphql_api(apiId=_a["apiId"]))
    return merged

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSchemaMerge on a MANUAL_MERGE association drives it to MERGE_SUCCESS with AppSync's
    exact status detail; a fabricated associationId is rejected with BadRequestException."""
    svc = ctx.client("appsync")
    source = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=source: svc.delete_graphql_api(apiId=_a["apiId"]))
    source_id = source["apiId"]

    svc.start_schema_creation(
        apiId=source_id, definition=b"schema { query: Query }\ntype Query { hello: String }"
    )
    _poll_until(
        lambda: svc.get_schema_creation_status(apiId=source_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=90,
        interval_s=2.0,
        description="source schema creation to reach a terminal state",
    )

    merged = _create_merged_api(ctx, svc)
    merged_id = merged["apiId"]

    assoc = svc.associate_merged_graphql_api(
        sourceApiIdentifier=source_id,
        mergedApiIdentifier=merged_id,
        sourceApiAssociationConfig={"mergeType": "MANUAL_MERGE"},
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]

    def _cleanup_disassociate():
        svc.disassociate_merged_graphql_api(
            sourceApiIdentifier=source_id, associationId=association_id
        )
        # DeleteGraphqlApi on the source rejects while the association still exists; its removal
        # is async, so the source-delete cleanup (registered before this one, thus run after it
        # under LIFO teardown) needs it actually gone first.
        _poll_until(
            lambda: _association_gone(svc, association_id, merged_id),
            lambda gone: gone,
            timeout_s=40,
            interval_s=2.0,
            description="association removal to propagate before the source API delete",
        )

    ctx.on_cleanup(_cleanup_disassociate)

    # Let any merge triggered automatically by the association settle first, so the manual
    # StartSchemaMerge below doesn't collide with it.
    _poll_until(
        lambda: svc.get_source_api_association(
            associationId=association_id, mergedApiIdentifier=merged_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] not in ("MERGE_SCHEDULED", "MERGE_IN_PROGRESS"),
        timeout_s=90,
        interval_s=3.0,
        description="initial association merge to settle",
    )

    merge_resp = svc.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_id)
    assert merge_resp.get("sourceApiAssociationStatus") in (
        "MERGE_SCHEDULED",
        "MERGE_IN_PROGRESS",
        "MERGE_SUCCESS",
    ), f"unexpected StartSchemaMerge status {merge_resp.get('sourceApiAssociationStatus')!r}"

    final = _poll_until(
        lambda: svc.get_source_api_association(
            associationId=association_id, mergedApiIdentifier=merged_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] not in ("MERGE_SCHEDULED", "MERGE_IN_PROGRESS"),
        timeout_s=90,
        interval_s=3.0,
        description="manual schema merge to reach a terminal state",
    )
    assert final["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"expected StartSchemaMerge to drive the association to MERGE_SUCCESS, got "
        f"{final['sourceApiAssociationStatus']!r}"
    )
    detail = final.get("sourceApiAssociationStatusDetail")
    assert detail == (
        f"Successfully merged source GraphQL API (API Id: {source_id}, Association Id: {association_id})"
    ), f"unexpected sourceApiAssociationStatusDetail: {detail!r}"

    fake_association_id = ctx.unique_name("sim2real_behav_assoc_").replace("-", "_")
    code, msg = _error(
        lambda: svc.start_schema_merge(associationId=fake_association_id, mergedApiIdentifier=merged_id)
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for StartSchemaMerge with a nonexistent associationId, got {code}"
    )
    assert msg == f"Invalid SourceApi Association ID {fake_association_id}", f"unexpected message: {msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
