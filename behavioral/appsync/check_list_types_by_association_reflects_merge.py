"""list-types-by-association-reflects-merge."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-types-by-association-reflects-merge"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a successful merge, ListTypesByAssociation exposes the source API's types."""
    appsync = ctx.client("appsync")

    source_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-lta-src-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _delete_graphql_api_quiet(appsync, source_id))

    # A MERGED Api requires an execution role AppSync can assume to read/merge the source
    # Apis' schemas -- CreateGraphqlApi rejects apiType="MERGED" outright with a
    # BadRequestException ("Merged API execution role must be specified") without one, even
    # for a manually-triggered merge.
    merge_role_arn = _create_merged_api_execution_role(ctx)

    merged_id = _create_merged_graphql_api_with_retry(ctx, appsync, merge_role_arn)
    ctx.on_cleanup(lambda: _delete_graphql_api_quiet(appsync, merged_id))

    appsync.create_type(
        apiId=source_id, definition="type Query {\n  ping: String\n}", format="SDL"
    )
    appsync.create_type(
        apiId=source_id,
        definition="type Widget {\n  id: ID!\n  label: String\n}",
        format="SDL",
    )

    assoc = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=source_id,
        mergedApiIdentifier=merged_id,
        sourceApiAssociationConfig={"mergeType": "MANUAL_MERGE"},
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]
    ctx.on_cleanup(lambda: _disassociate_merged_quiet(appsync, source_id, association_id))

    # AssociateMergedGraphqlApi itself finishes asynchronously: for a short window right
    # after it returns, the association still has that association operation "in progress"
    # from AppSync's perspective, and StartSchemaMerge on it fails with
    # ConcurrentModificationException even though the SDK call already returned. Retry
    # StartSchemaMerge across a bounded window instead of treating that as fatal.
    _start_schema_merge_with_retry(appsync, association_id, merged_id)

    def _probe():
        return appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"]

    final = _poll_until(
        _probe,
        lambda a: a["sourceApiAssociationStatus"]
        in ("MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert final["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"merge ended in {final['sourceApiAssociationStatus']!r}: "
        f"{final.get('sourceApiAssociationStatusDetail')}"
    )

    type_names = _collect_type_names(appsync, merged_id, association_id)
    assert "Widget" in type_names, (
        f"ListTypesByAssociation via {association_id} did not surface the source API's "
        f"Widget type; got {sorted(type_names)}"
    )
    assert "Query" in type_names, (
        f"ListTypesByAssociation via {association_id} did not surface the source API's "
        f"Query type; got {sorted(type_names)}"
    )


def _error_code_from_exc(exc: Exception) -> str | None:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code")
    return None


def _delete_graphql_api_quiet(appsync: Any, api_id: str) -> None:
    try:
        appsync.delete_graphql_api(apiId=api_id)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "NotFoundException":
            raise


def _disassociate_merged_quiet(appsync: Any, source_id: str, association_id: str) -> None:
    try:
        appsync.disassociate_merged_graphql_api(
            sourceApiIdentifier=source_id, associationId=association_id
        )
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "NotFoundException":
            raise


def _create_merged_api_execution_role(ctx) -> str:
    """Create an IAM role AppSync can assume to merge source Apis into a Merged Api."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appsync-merge-")[:64]
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
    ctx.on_cleanup(lambda: _delete_role_quiet(iam, role_name))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "appsync:*", "Resource": "*"}],
        }
    )
    policy_name = "sim2real-appsync-merge-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: _delete_role_policy_quiet(iam, role_name, policy_name))

    return role_arn


def _create_merged_graphql_api_with_retry(
    ctx, appsync: Any, role_arn: str, timeout_s: float = 60.0, interval_s: float = 3.0
) -> str:
    """A freshly-minted execution role's trust policy needs a short window to propagate to the
    AppSync control plane before CreateGraphqlApi will accept it as the mergedApiExecutionRoleArn
    -- poll the call we actually care about (which rejects the still-propagating role with
    BadRequestException) instead of sleeping blindly."""
    name = ctx.unique_name("sim2real-appsync-lta-merged-")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )["graphqlApi"]["apiId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"CreateGraphqlApi with MERGED apiType kept rejecting the execution role within "
        f"{timeout_s}s: {last_exc}"
    )


def _delete_role_quiet(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_policy_quiet(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _start_schema_merge_with_retry(
    appsync: Any, association_id: str, merged_id: str, timeout_s: float = 60.0, interval_s: float = 3.0
) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            appsync.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_id)
            return
        except Exception as exc:  # noqa: BLE001
            if _error_code_from_exc(exc) != "ConcurrentModificationException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _collect_type_names(appsync: Any, merged_id: str, association_id: str) -> set[str]:
    names: set[str] = set()
    token = None
    pages = 0
    while True:
        kwargs = {
            "mergedApiIdentifier": merged_id,
            "associationId": association_id,
            "format": "SDL",
            "maxResults": 25,
        }
        if token:
            kwargs["nextToken"] = token
        resp = appsync.list_types_by_association(**kwargs)
        for t in resp.get("types", []):
            names.add(t["name"])
        pages += 1
        token = resp.get("nextToken")
        if not token or pages > 50:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
