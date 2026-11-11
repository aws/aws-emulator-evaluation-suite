"""concurrent-associate-merged-graphql-api-conflict."""
from __future__ import annotations

import json
import threading
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-associate-merged-graphql-api-conflict"
GROUP = "concurrency"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent AssociateMergedGraphqlApi calls for one source/merged pair create exactly
    one association; the other is refused with ConcurrentModificationException (overlapping) or
    BadRequestException (after the winner) with its exact message, never a second association."""
    appsync = ctx.client("appsync")

    source_api_id = _create_graphql_api(ctx, appsync, "sim2real-appsync-src")
    role_arn = _create_merge_role(ctx)
    merged_api_id = _create_merged_api(ctx, appsync, role_arn)

    barrier = threading.Barrier(2)
    results: list[dict[str, Any]] = [{}, {}]

    def _associate(idx: int) -> None:
        barrier.wait(timeout=10)
        try:
            resp = appsync.associate_merged_graphql_api(
                sourceApiIdentifier=source_api_id,
                mergedApiIdentifier=merged_api_id,
            )
            results[idx] = {
                "ok": True,
                "associationId": resp["sourceApiAssociation"]["associationId"],
            }
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            message = resp.get("Error", {}).get("Message") if isinstance(resp, dict) else str(exc)
            results[idx] = {"ok": False, "code": _error_code(exc), "message": message}

    t1 = threading.Thread(target=_associate, args=(0,))
    t2 = threading.Thread(target=_associate, args=(1,))
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)

    successes = [r for r in results if r.get("ok")]
    failures = [r for r in results if not r.get("ok")]

    assert len(successes) == 1, f"expected exactly one winning association, got {results}"
    assert len(failures) == 1, f"expected exactly one refused association, got {results}"
    # A loser overlapping the winner is told the associations are being updated; one arriving
    # after it sees the association already in place (or the source already bound to this API).
    accepted = {
        "ConcurrentModificationException": {
            f"SourceApiAssociations for Merged API {merged_api_id} are currently being updated, "
            "please wait and try again."
        },
        "BadRequestException": {
            "SourceApiAssociation already exists.",
            "Source Api can not be associated with multiple Merged APIs.",
        },
    }
    loser = failures[0]
    assert loser["code"] in accepted, (
        f"expected ConcurrentModificationException or BadRequestException on the loser, got {loser}"
    )
    assert loser["message"] in accepted[loser["code"]], (
        f"unexpected {loser['code']} message: {loser['message']!r}; "
        f"expected one of {sorted(accepted[loser['code']])}"
    )

    winning_association_id = successes[0]["associationId"]
    ctx.on_cleanup(
        lambda: _safe_disassociate(appsync, source_api_id, merged_api_id, winning_association_id)
    )

    summaries = appsync.list_source_api_associations(apiId=merged_api_id)[
        "sourceApiAssociationSummaries"
    ]
    matching = [s for s in summaries if s["associationId"] == winning_association_id]
    assert len(matching) == 1, (
        f"expected exactly one active source API association on the merged API, got {summaries}"
    )
    assert len(summaries) == 1, (
        f"expected no duplicate association created by the losing call, got {summaries}"
    )


def _error_code(exc: Exception) -> str | None:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code")
    return None


def _create_graphql_api(ctx, appsync, prefix: str) -> str:
    name = ctx.unique_name(f"{prefix}-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _create_merge_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appsync-merge-role-")
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-appsync-merge-policy"
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["appsync:SourceGraphQL", "appsync:StartSchemaMerge"],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_merged_api(ctx, appsync, role_arn: str) -> str:
    name = ctx.unique_name("sim2real-appsync-merged-")
    deadline = time.monotonic() + 30
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )
            merged_api_id = resp["graphqlApi"]["apiId"]
            ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=merged_api_id))
            return merged_api_id
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if _error_code(exc) == "BadRequestException":
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create merged API after role propagation wait: {last_exc}")


def _safe_disassociate(appsync, source_api_id: str, merged_api_id: str, association_id: str) -> None:
    try:
        appsync.disassociate_merged_graphql_api(
            sourceApiIdentifier=source_api_id, associationId=association_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    # DisassociateMergedGraphqlApi tears the association down asynchronously; deleting either
    # API while it is still winding down is rejected, so wait for it to disappear (bounded, best
    # effort — the outer cleanup budget is shared with the deletes still queued behind this one).
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            appsync.get_source_api_association(
                associationId=association_id, mergedApiIdentifier=merged_api_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
