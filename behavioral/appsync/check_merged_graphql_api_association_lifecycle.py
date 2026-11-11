"""merged-graphql-api-association-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "merged-graphql-api-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["appsync"]

_TERMINAL = {"MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateMergedGraphqlApi creates a merged-API association that reaches MERGE_SUCCESS,
    and DisassociateMergedGraphqlApi correctly tears it down."""
    appsync = ctx.client("appsync")

    source = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-src-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK},
    )["graphqlApi"]
    source_id, source_arn = source["apiId"], source["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=source_id)))

    # A merge needs something to merge: an API with no schema fails with MERGE_FAILED
    # ("There's no types found in this API"), which is not the happy path this check names.
    _create_schema(appsync, source_id, "type Query {\n  hello: String\n}\n")

    role_arn = _create_merged_api_role(ctx, source_arn)

    merged = _create_merged_api_with_retry(
        appsync, ctx.unique_name("sim2real-appsync-merged-"), role_arn
    )["graphqlApi"]
    merged_id = merged["apiId"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=merged_id)))

    assoc = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=source_id,
        mergedApiIdentifier=merged_id,
        description="sim2real-merge-test",
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: appsync.disassociate_merged_graphql_api(
                sourceApiIdentifier=source_id, associationId=association_id
            )
        )
    )

    final = _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] in _TERMINAL,
        timeout_s=180,
        interval_s=5,
    )
    assert final["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"expected MERGE_SUCCESS on the happy path, got "
        f"{final['sourceApiAssociationStatus']!r}: {final}"
    )
    assert final["sourceApiId"] == source_id, (
        f"expected sourceApiId={source_id!r}, got {final['sourceApiId']!r}"
    )
    assert final["mergedApiId"] == merged_id, (
        f"expected mergedApiId={merged_id!r}, got {final['mergedApiId']!r}"
    )
    assert final["description"] == "sim2real-merge-test", (
        f"expected description='sim2real-merge-test', got {final['description']!r}"
    )

    appsync.disassociate_merged_graphql_api(sourceApiIdentifier=source_id, associationId=association_id)

    def _removed() -> bool:
        summaries = appsync.list_source_api_associations(apiId=merged_id).get(
            "sourceApiAssociationSummaries", []
        )
        return not any(s["associationId"] == association_id for s in summaries)

    torn_down = _poll_until(_removed, lambda r: r is True, timeout_s=120, interval_s=5)
    assert torn_down is True, "association should no longer be listed after DisassociateMergedGraphqlApi"

    # gone means gone, not just unlisted: a targeted read 404s, and a second
    # DisassociateMergedGraphqlApi on the same (now-dead) id fails the same way.
    get_code, get_message = _error(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )
    )
    assert get_code == "NotFoundException", (
        f"expected NotFoundException reading the removed association, got {get_code}"
    )
    assert get_message == "No source API association was found", get_message

    redisassociate_code, redisassociate_message = _error(
        lambda: appsync.disassociate_merged_graphql_api(
            sourceApiIdentifier=source_id, associationId=association_id
        )
    )
    assert redisassociate_code == "NotFoundException", (
        f"expected a second DisassociateMergedGraphqlApi on the dead association to fail "
        f"with NotFoundException, got {redisassociate_code}"
    )
    assert redisassociate_message == "No source API association was found", redisassociate_message


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


def _create_schema(appsync, api_id: str, sdl: str) -> None:
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return
        if status == "FAILED":
            raise AssertionError("schema creation failed")
        time.sleep(3.0)
    raise AssertionError("schema creation did not complete in time")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_merged_api_role(ctx, source_api_arn: str) -> str:
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="source-graphql")))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="source-graphql",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "appsync:SourceGraphQL",
                        "Resource": [source_api_arn, f"{source_api_arn}/*"],
                    }
                ],
            }
        ),
    )
    return role_arn


def _create_merged_api_with_retry(appsync, name: str, role_arn: str, timeout_s: float = 60.0):
    """CreateGraphqlApi(apiType=MERGED) validates it can assume role_arn at creation time and
    returns BadRequestException until the just-created role/trust-policy has propagated to
    AppSync -- retry that window instead of guessing a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK},
            )
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] == "BadRequestException":
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create merged API after role propagation wait: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
