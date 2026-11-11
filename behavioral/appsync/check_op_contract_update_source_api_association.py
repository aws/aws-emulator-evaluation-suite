"""op-contract-update-source-api-association."""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-update-source-api-association"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """UpdateSourceApiAssociation persists a new description on a real
    source<->merged API association, and rejects an unknown associationId."""
    appsync = ctx.client("appsync")

    source_api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-src-"), authenticationType="API_KEY"
    )["graphqlApi"]
    source_id = source_api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=source_id))

    merged_id = _create_merged_graphql_api(ctx)

    try:
        assoc = appsync.associate_source_graphql_api(
            mergedApiIdentifier=merged_id,
            sourceApiIdentifier=source_id,
            description="initial-description",
        )["sourceApiAssociation"]
    except Exception as exc:  # pragma: no cover - environment without merged-API support
        raise AssertionError(
            f"unreachable: AssociateSourceGraphqlApi not usable in this account: {exc}"
        )

    association_id = assoc["associationId"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(appsync, merged_id, association_id))

    # AssociateSourceGraphqlApi kicks off an async merge (MERGE_SCHEDULED -> MERGE_IN_PROGRESS);
    # updating the association while that merge is in flight races the control plane and is
    # rejected with ConcurrentModificationException. Wait for it to settle first.
    _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"],
        lambda a: (
            a.get("sourceApiAssociationStatus") not in ("MERGE_SCHEDULED", "MERGE_IN_PROGRESS")
        ),
        timeout_s=90,
        interval_s=2.0,
        description="source api association leaving the in-progress merge state",
    )

    # success path: update the description
    updated = appsync.update_source_api_association(
        associationId=association_id,
        mergedApiIdentifier=merged_id,
        description="updated-description",
    )["sourceApiAssociation"]
    assert updated["description"] == "updated-description", (
        f"expected the mutating call's own response to echo the new description, got {updated['description']!r}"
    )
    assert updated["associationId"] == association_id, (
        f"expected associationId {association_id!r} unchanged by the update, got {updated['associationId']!r}"
    )
    assert updated["sourceApiId"] == source_id, (
        f"expected sourceApiId {source_id!r} unchanged by the update, got {updated['sourceApiId']!r}"
    )
    assert updated["mergedApiId"] == merged_id, (
        f"expected mergedApiId {merged_id!r} unchanged by the update, got {updated['mergedApiId']!r}"
    )

    fetched = appsync.get_source_api_association(
        mergedApiIdentifier=merged_id, associationId=association_id
    )["sourceApiAssociation"]
    assert fetched["description"] == "updated-description", (
        f"expected an independent GetSourceApiAssociation read to see the persisted description, "
        f"got {fetched['description']!r}"
    )

    # error boundary: an associationId that does not exist on this merged API.
    # AppSync validates the associationId's shape/lineage before doing a lookup, so an
    # arbitrary non-existent id is rejected as a malformed request (BadRequestException)
    # rather than surfacing as a NotFoundException.
    bogus_association_id = "nonexistent-association-id"
    code, message = _error(
        lambda: appsync.update_source_api_association(
            associationId=bogus_association_id,
            mergedApiIdentifier=merged_id,
            description="should-not-apply",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == f"Invalid SourceApi Association ID {bogus_association_id}", (
        f"unexpected BadRequestException message {message!r}"
    )

    unaffected = appsync.get_source_api_association(
        mergedApiIdentifier=merged_id, associationId=association_id
    )["sourceApiAssociation"]
    assert unaffected["description"] == "updated-description", (
        "rejected update must not mutate the association"
    )


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _disassociate_and_wait(appsync, merged_id: str, association_id: str) -> None:
    """Disassociation is asynchronous; neither API can be deleted until the association is gone."""
    from botocore.exceptions import ClientError

    appsync.disassociate_source_graphql_api(
        mergedApiIdentifier=merged_id, associationId=association_id
    )

    def _gone() -> bool:
        try:
            appsync.get_source_api_association(
                mergedApiIdentifier=merged_id, associationId=association_id
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return True
            raise
        return False

    _poll_until(
        _gone, bool, timeout_s=180, interval_s=3.0, description="source api association removed"
    )


def _create_merged_graphql_api(ctx) -> str:
    """A MERGED API requires an execution role (mergedApiExecutionRoleArn); create one."""
    from botocore.exceptions import ClientError

    appsync = ctx.client("appsync")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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
        lambda: _safe(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="SourceGraphQLAccess")
        )
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


def _safe(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "NotFoundException"):
            raise


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
