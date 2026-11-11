"""list-types-by-association-ordering."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-types-by-association-ordering"
GROUP = "ordering"
SERVICES = ["appsync"]

_MERGE_TIMEOUT_S = 240.0
_MERGE_POLL_S = 2.0
_ROLE_PROPAGATION_TIMEOUT_S = 60.0
_ROLE_PROPAGATION_POLL_S = 5.0

_TYPES_SDL = {
    "Query": "type Query { getWidgetA: WidgetA getWidgetB: WidgetB getWidgetC: WidgetC }",
    "WidgetA": "type WidgetA { id: ID }",
    "WidgetB": "type WidgetB { id: ID }",
    "WidgetC": "type WidgetC { id: ID }",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTypesByAssociation returns the merged types for a source-API association in a
    stable, repeatable order across two full paginated traversals."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    # A Merged API requires an execution role AppSync can assume to read/associate its source
    # APIs -- CreateGraphqlApi rejects apiType=MERGED without mergedApiExecutionRoleArn with
    # BadRequestException. Create + attach that role first.
    role_name = ctx.unique_name("sim2real-merged-role-")
    role_arn = _create_merged_api_role(iam, role_name)
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))

    merged_name = ctx.unique_name("sim2real-merged-")
    source_name = ctx.unique_name("sim2real-source-")
    merged_api_id = _create_merged_graphql_api_with_retry(appsync, merged_name, role_arn)
    ctx.on_cleanup(lambda: _safe_delete_graphql_api(appsync, merged_api_id))

    source_api_id = appsync.create_graphql_api(
        name=source_name,
        authenticationType="API_KEY",
        apiType="GRAPHQL",
        tags={"sim2real-check": CHECK},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe_delete_graphql_api(appsync, source_api_id))

    for definition in _TYPES_SDL.values():
        appsync.create_type(apiId=source_api_id, definition=definition, format="SDL")

    association = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=source_api_id,
        mergedApiIdentifier=merged_api_id,
        sourceApiAssociationConfig={"mergeType": "MANUAL_MERGE"},
    )["sourceApiAssociation"]
    association_id = association["associationId"]
    ctx.on_cleanup(
        lambda: _safe_disassociate(appsync, source_api_id, merged_api_id, association_id)
    )

    _start_schema_merge_with_retry(appsync, association_id, merged_api_id)

    status = _poll_merge_status(appsync, merged_api_id, association_id)
    if status != "MERGE_SUCCESS":
        raise AssertionError(
            f"source API merge did not reach MERGE_SUCCESS in time (status={status})"
        )

    pass1 = _list_all_types_by_association(appsync, merged_api_id, association_id, page_size=1)
    pass2 = _list_all_types_by_association(appsync, merged_api_id, association_id, page_size=1)

    assert set(_TYPES_SDL) <= set(pass1), (
        f"expected merged types {sorted(_TYPES_SDL)} to be present, got {sorted(pass1)}"
    )
    assert pass1 == pass2, (
        f"ListTypesByAssociation order was not stable across repeated full scans: "
        f"{pass1!r} != {pass2!r}"
    )
    assert len(pass1) == len(set(pass1)), "ListTypesByAssociation returned a duplicate type in one traversal"


# ===== helpers =====

def _create_merged_api_role(iam: Any, role_name: str) -> str:
    """Create the IAM role a Merged API's execution role must be -- trusted by appsync.amazonaws.com
    and permitted to associate source APIs. Returns the role ARN."""
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "appsync:SourceGraphQLApiAssociation",
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-merged-api-association",
        PolicyDocument=json.dumps(permissions_policy),
    )
    return role_arn


def _create_merged_graphql_api_with_retry(appsync: Any, name: str, role_arn: str) -> str:
    """CreateGraphqlApi(apiType=MERGED) can reject a freshly-created role with
    BadRequestException until IAM propagation catches up -- retry within a bounded window
    rather than failing on the very first eventually-consistent read."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real-check": CHECK},
            )["graphqlApi"]["apiId"]
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "BadRequestException":
                last_exc = exc
                time.sleep(_ROLE_PROPAGATION_POLL_S)
                continue
            raise
    assert last_exc is not None, (
        f"create_graphql_api(apiType=MERGED) never ran within {_ROLE_PROPAGATION_TIMEOUT_S}s"
    )
    raise last_exc


def _safe_delete_role(iam: Any, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-merged-api-association")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _start_schema_merge_with_retry(appsync: Any, association_id: str, merged_api_id: str) -> None:
    """The association is left with an operation in progress (e.g. the implicit initial merge
    kicked off by AssociateMergedGraphqlApi) for a bit after creation -- StartSchemaMerge raises
    ConcurrentModificationException ("This association currently has an operation ... in
    progress") until that settles. Retry within a bounded window rather than failing on the very
    first attempt."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            appsync.start_schema_merge(
                associationId=association_id, mergedApiIdentifier=merged_api_id
            )
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ConcurrentModificationException":
                last_exc = exc
                time.sleep(_ROLE_PROPAGATION_POLL_S)
                continue
            raise
    assert last_exc is not None, (
        f"start_schema_merge never ran within {_ROLE_PROPAGATION_TIMEOUT_S}s"
    )
    raise last_exc


def _poll_merge_status(appsync: Any, merged_api_id: str, association_id: str) -> str:
    deadline = time.monotonic() + _MERGE_TIMEOUT_S
    last_status = "UNKNOWN"
    while time.monotonic() < deadline:
        resp = appsync.get_source_api_association(
            associationId=association_id, mergedApiIdentifier=merged_api_id
        )["sourceApiAssociation"]
        last_status = resp.get("sourceApiAssociationStatus", "UNKNOWN")
        if last_status in ("MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED"):
            return last_status
        time.sleep(_MERGE_POLL_S)
    return last_status


def _list_all_types_by_association(
    appsync: Any, merged_api_id: str, association_id: str, page_size: int
) -> list[str]:
    names: list[str] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {
            "mergedApiIdentifier": merged_api_id,
            "associationId": association_id,
            "format": "SDL",
            "maxResults": page_size,
        }
        if token:
            kwargs["nextToken"] = token
        resp = appsync.list_types_by_association(**kwargs)
        names.extend(t["name"] for t in resp.get("types", []))
        token = resp.get("nextToken")
        if not token:
            break
    return names


def _safe_disassociate(appsync: Any, source_api_id: str, merged_api_id: str, association_id: str) -> None:
    try:
        appsync.disassociate_merged_graphql_api(
            sourceApiIdentifier=source_api_id, associationId=association_id
        )
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            try:
                appsync.get_source_api_association(
                    associationId=association_id, mergedApiIdentifier=merged_api_id
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise
                break
            time.sleep(3.0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_delete_graphql_api(appsync: Any, api_id: str) -> None:
    deadline = time.monotonic() + 90.0
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            appsync.delete_graphql_api(apiId=api_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "ConcurrentModificationException":
                last_exc = exc
                time.sleep(4.0)
                continue
            raise
    if last_exc is not None:
        raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
