"""merged-api-disassociate-wrong-source-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "merged-api-disassociate-wrong-source-rejected"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateMergedGraphqlApi rejects an associationId scoped to a different
    sourceApiIdentifier than the one that owns it (NotFoundException) and leaves the real
    association intact; the correctly-scoped call still succeeds."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    source_api_id = _create_graphql_api_with_schema(ctx, appsync, "sim2real-behav-wrongsrc-")
    unrelated_api_id = _create_graphql_api(ctx, appsync, "sim2real-behav-unrelated-")
    merge_role_arn = _create_merge_execution_role(ctx, iam)
    merged_api_id = _create_merged_graphql_api(
        ctx, appsync, "sim2real-behav-wrongmerged-", merge_role_arn
    )

    assoc = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=source_api_id, mergedApiIdentifier=merged_api_id
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]
    ctx.on_cleanup(lambda: _safe_disassociate_merged(appsync, source_api_id, association_id))

    # AssociateMergedGraphqlApi kicks off an async schema merge; while it's still
    # MERGE_IN_PROGRESS, AppSync rejects ANY DisassociateMergedGraphqlApi call (right- or
    # wrong-scoped) with ConcurrentModificationException. Wait for the merge to settle into a
    # terminal status before exercising the disassociate-with-wrong-source rejection so the
    # ConcurrentModificationException we observe is the one this check is actually about.
    merge_status = _poll_merge_status(appsync, merged_api_id, association_id, timeout_s=180, interval_s=5)
    if merge_status not in ("MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED"):
        raise AssertionError(
            f"source API merge did not reach a terminal status within 180s (still {merge_status!r})",
        )

    # Break exactly one precondition: disassociate using an sourceApiIdentifier that did
    # not create this association.
    err, err_message = _error(
        lambda: appsync.disassociate_merged_graphql_api(
            sourceApiIdentifier=unrelated_api_id, associationId=association_id
        )
    )
    assert err == "NotFoundException", (
        f"expected NotFoundException disassociating with a mismatched sourceApiIdentifier, got {err!r}"
    )
    assert err_message == "No source API association was found", err_message

    # The forbidden effect did not happen: the real association is still intact.
    still_there = appsync.get_source_api_association(
        mergedApiIdentifier=merged_api_id, associationId=association_id
    )["sourceApiAssociation"]
    assert still_there["sourceApiId"] == source_api_id, (
        f"expected the association's sourceApiId to remain {source_api_id!r}, got "
        f"{still_there['sourceApiId']!r}"
    )
    assert still_there["associationId"] == association_id, (
        f"expected the association's associationId to remain {association_id!r}, got "
        f"{still_there['associationId']!r}"
    )

    # Positive control: the correctly-scoped call succeeds and the link is removed.
    appsync.disassociate_merged_graphql_api(
        sourceApiIdentifier=source_api_id, associationId=association_id
    )
    removed = _poll_until(
        lambda: _list_association_ids(appsync, source_api_id),
        lambda ids: association_id not in ids,
        timeout_s=120,
        interval_s=5,
    )
    assert removed, "correctly-scoped DisassociateMergedGraphqlApi never removed the association"


_SOURCE_SCHEMA = b"schema { query: Query }\ntype Query { hello: String }\n"


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, so an
    over-permissive target cannot pass this as a code mismatch instead of a missing rejection."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return True
        time.sleep(interval_s)
        result = probe()
    return predicate(result)


def _poll_merge_status(appsync, merged_api_id: str, association_id: str, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_source_api_association(
            mergedApiIdentifier=merged_api_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"]
        if status not in ("MERGE_IN_PROGRESS", "DELETION_IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    return status


def _create_graphql_api(ctx, appsync, prefix: str, *, api_type: str = "GRAPHQL") -> str:
    name = ctx.unique_name(prefix)
    kwargs = {
        "name": name,
        "authenticationType": "API_KEY",
        "tags": {"sim2real": CHECK, "sim2real:managed": "true"},
    }
    if api_type != "GRAPHQL":
        kwargs["apiType"] = api_type
    api_id = appsync.create_graphql_api(**kwargs)["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe_delete_graphql_api(appsync, api_id))
    return api_id


def _create_graphql_api_with_schema(ctx, appsync, prefix: str) -> str:
    api_id = _create_graphql_api(ctx, appsync, prefix)
    appsync.start_schema_creation(apiId=api_id, definition=_SOURCE_SCHEMA)
    deadline = time.monotonic() + 60
    status = "PROCESSING"
    while time.monotonic() < deadline and status == "PROCESSING":
        time.sleep(3)
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
    if status != "SUCCESS":
        raise AssertionError(f"source API schema creation did not reach SUCCESS, got {status!r}")
    return api_id


def _create_merge_execution_role(ctx, iam) -> str:
    """CreateGraphqlApi for apiType=MERGED requires a mergedApiExecutionRoleArn -- the IAM
    role AppSync assumes to read the source API's schema/types during a merge."""
    role_name = ctx.unique_name("sim2real-behav-mergerole-")
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
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    policy_doc = json.dumps(
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
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-merge-policy", PolicyDocument=policy_doc
    )
    ctx.on_cleanup(
        lambda: _safe_delete_role_policy(iam, role_name, "sim2real-behav-merge-policy")
    )
    return role_arn


def _create_merged_graphql_api(ctx, appsync, prefix: str, merge_role_arn: str) -> str:
    """A freshly-created IAM role is not immediately assumable everywhere (IAM's
    eventual-consistency window), so CreateGraphqlApi for a MERGED api can transiently
    reject the still-propagating role; retry within a bounded window rather than failing
    on the first attempt."""
    from botocore.exceptions import ClientError

    name = ctx.unique_name(prefix)
    deadline = time.monotonic() + 30
    while True:
        try:
            api_id = appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=merge_role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )["graphqlApi"]["apiId"]
            ctx.on_cleanup(lambda: _safe_delete_graphql_api(appsync, api_id))
            return api_id
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _safe_delete_role(iam, role_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _list_association_ids(appsync, source_api_id: str) -> set:
    ids = set()
    next_token = None
    while True:
        kwargs = {"apiId": source_api_id}
        if next_token:
            kwargs["nextToken"] = next_token
        page = appsync.list_source_api_associations(**kwargs)
        for entry in page.get("sourceApiAssociationSummaries", []):
            ids.add(entry["associationId"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    return ids


def _safe_delete_graphql_api(appsync, api_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appsync.delete_graphql_api(apiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_disassociate_merged(appsync, source_api_id: str, association_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appsync.disassociate_merged_graphql_api(
            sourceApiIdentifier=source_api_id, associationId=association_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
