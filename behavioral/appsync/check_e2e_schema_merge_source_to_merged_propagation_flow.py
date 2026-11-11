"""e2e-schema-merge-source-to-merged-propagation-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-schema-merge-source-to-merged-propagation-flow"
GROUP = "e2e"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating a source API and running StartSchemaMerge causes the merged API's schema
    to actually gain the source's types, and disassociating removes them again."""
    appsync = ctx.client("appsync")

    # --- source API with a distinctive custom type ---
    source_name = ctx.unique_name("sim2real-src-")
    source_api = appsync.create_graphql_api(
        name=source_name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    source_api_id = source_api["apiId"]
    source_api_arn = source_api["arn"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=source_api_id))

    type_name = "".join(ch for ch in ctx.unique_name("BehavWidget") if ch.isalnum())
    schema_def = f"type {type_name} {{ id: String }}\ntype Query {{ getBehavWidget: {type_name} }}\n"
    appsync.start_schema_creation(apiId=source_api_id, definition=schema_def.encode("utf-8"))
    schema_status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=source_api_id)["status"],
        lambda status: status in ("SUCCESS", "FAILED"),
        timeout_s=60,
        interval_s=2,
    )
    assert schema_status == "SUCCESS", schema_status

    # --- merged API + execution role that lets it pull from the source API ---
    role_arn = _create_merge_execution_role(ctx, source_api_arn)

    merged_name = ctx.unique_name("sim2real-merged-")
    merged_api = appsync.create_graphql_api(
        name=merged_name,
        authenticationType="API_KEY",
        apiType="MERGED",
        mergedApiExecutionRoleArn=role_arn,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    merged_api_id = merged_api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=merged_api_id))

    # --- associate + merge, retrying briefly for IAM role propagation ---
    association = _retry_on_bad_request(
        lambda: appsync.associate_merged_graphql_api(
            sourceApiIdentifier=source_api_id, mergedApiIdentifier=merged_api_id
        )["sourceApiAssociation"],
        timeout_s=60,
    )
    association_id = association["associationId"]

    _TERMINAL = ("MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED")

    def _assoc_status() -> str:
        return appsync.get_source_api_association(
            mergedApiIdentifier=merged_api_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"]

    # Association creation itself schedules an automatic initial merge. Let that settle to a
    # terminal state first, otherwise an explicit StartSchemaMerge races it and AppSync rejects
    # the call with ConcurrentModificationException ("operation in progress").
    _poll_until(_assoc_status, lambda status: status in _TERMINAL, timeout_s=120, interval_s=5)

    _retry_on_bad_request(
        lambda: appsync.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_api_id),
        timeout_s=60,
    )

    merged_status = _poll_until(_assoc_status, lambda status: status in _TERMINAL, timeout_s=120, interval_s=5)
    assert merged_status == "MERGE_SUCCESS", merged_status

    # The association's own type listing reflects the source schema's types.
    assoc_types = appsync.list_types_by_association(
        mergedApiIdentifier=merged_api_id, associationId=association_id, format="SDL"
    )["types"]
    assoc_type_names = {t["name"] for t in assoc_types}
    assert type_name in assoc_type_names, assoc_type_names

    # The merged API's *actual* schema also gained the type (not just the association's cache).
    merged_type = appsync.get_type(apiId=merged_api_id, typeName=type_name, format="SDL")["type"]
    assert "id" in merged_type["definition"], merged_type["definition"]

    # --- disassociate; the merged API should lose the source's type again ---
    appsync.disassociate_merged_graphql_api(sourceApiIdentifier=source_api_id, associationId=association_id)

    def _association_gone_or_deleting():
        return _error(
            lambda: appsync.get_source_api_association(
                mergedApiIdentifier=merged_api_id, associationId=association_id
            )
        )

    removed_code, removed_message = _poll_until(
        _association_gone_or_deleting,
        lambda err: err[0] == "NotFoundException",
        timeout_s=120,
        interval_s=5,
    )
    assert removed_code == "NotFoundException", removed_code
    assert removed_message == "No source API association was found", removed_message

    type_gone_code, type_gone_message = _poll_until(
        lambda: _error(lambda: appsync.get_type(apiId=merged_api_id, typeName=type_name, format="SDL")),
        lambda err: err[0] == "NotFoundException",
        timeout_s=60,
        interval_s=5,
    )
    assert type_gone_code == "NotFoundException", type_gone_code
    assert type_gone_message == "Type not found.", type_gone_message


def _create_merge_execution_role(ctx, source_api_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appsync-merge-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-source-graphql"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "appsync:SourceGraphQL",
                "Resource": [source_api_arn, f"{source_api_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


_CALL_SUCCEEDED = "<call succeeded>"


def _error(fn):
    """Return fn()'s botocore error (code, message), or a sentinel code no error can equal on success."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _CALL_SUCCEEDED, None


def _retry_on_bad_request(fn, *, timeout_s: float):
    """IAM role trust/permissions can take a few seconds to propagate to AppSync, and
    StartSchemaMerge can transiently race a still-settling association state."""
    from botocore.exceptions import ClientError

    retryable = ("BadRequestException", "ConcurrentModificationException")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in retryable:
                raise
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"operation kept failing with a retryable error: {last_exc}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
