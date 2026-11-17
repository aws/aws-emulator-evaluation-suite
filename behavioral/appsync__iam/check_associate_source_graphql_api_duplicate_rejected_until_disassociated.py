"""associate-source-graphql-api-duplicate-rejected-until-disassociated."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-source-graphql-api-duplicate-rejected-until-disassociated"
GROUP = "source-api-associations"
SERVICES = ["appsync", "iam"]

_DUPLICATE_ASSOCIATION = ("BadRequestException", "SourceApiAssociation already exists.")
_ASSOCIATION_NOT_FOUND = ("NotFoundException", "No source API association was found")
_ASSOCIATION_BUSY = (
    "ConcurrentModificationException",
    "This association currently has an operation in progress, please wait until that is complete",
)
_SOURCE_STILL_ASSOCIATED = (
    "BadRequestException",
    "API can not be deleted as it is associated to a Merged API",
)


def expect_error(fn, code: str, message: str) -> None:
    """Asserts fn() raises exactly (code, message); an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_code, got_message = err.get("Code"), err.get("Message")
        assert got_code == code, f"expected error code {code!r}, got {got_code!r}: {got_message!r}"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected {code} to be raised, but the call succeeded: {result!r}")


def _disassociate(appsync, merged_id: str, association_id: str, *, budget_s: float = 180.0) -> None:
    """Removes an association, retrying while a scheduled merge still has it busy."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            appsync.disassociate_source_graphql_api(
                mergedApiIdentifier=merged_id, associationId=association_id
            )
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message")
            if code == "NotFoundException":
                return
            if (code, message) == _ASSOCIATION_BUSY and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _wait_until_removed(appsync, merged_id: str, association_id: str, *, budget_s: float = 180.0) -> None:
    """Polls GetSourceApiAssociation to its terminal NotFoundException, asserting the exact message."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            appsync.get_source_api_association(mergedApiIdentifier=merged_id, associationId=association_id)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message")
            assert code == _ASSOCIATION_NOT_FOUND[0], f"removal ended in {code!r}: {message!r}"
            assert message == _ASSOCIATION_NOT_FOUND[1], f"unexpected NotFoundException message {message!r}"
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"association {association_id!r} still present after {budget_s}s")
        time.sleep(3.0)


def _delete_source_api(appsync, source_id: str, *, budget_s: float = 180.0) -> None:
    """Deletes the source API, retrying while AWS still reflects it as associated to a merged API."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            appsync.delete_graphql_api(apiId=source_id)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message")
            if (code, message) == _SOURCE_STILL_ASSOCIATED and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second AssociateSourceGraphqlApi on an already-associated pair is refused with the
    original association the only one listed, and the pair re-associates once
    GetSourceApiAssociation reports the removed association gone.
    """
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    source_name = ctx.unique_name("sim2real-behav-appsync-src-")
    merged_name = ctx.unique_name("sim2real-behav-appsync-mrg-")
    role_name = ctx.unique_name("sim2real-behav-appsync-mergerole-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    source_api = appsync.create_graphql_api(
        name=source_name, authenticationType="API_KEY", apiType="GRAPHQL"
    )["graphqlApi"]
    source_id = source_api["apiId"]
    ctx.on_cleanup(lambda: _delete_source_api(appsync, source_id))

    merged_api = appsync.create_graphql_api(
        name=merged_name, authenticationType="API_KEY", apiType="MERGED",
        mergedApiExecutionRoleArn=role_arn,
    )["graphqlApi"]
    merged_id = merged_api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=merged_id))

    first = appsync.associate_source_graphql_api(
        mergedApiIdentifier=merged_id, sourceApiIdentifier=source_id
    )["sourceApiAssociation"]
    first_id = first["associationId"]
    assert first["sourceApiId"] == source_id, f"association recorded source {first['sourceApiId']!r}"
    assert first["mergedApiId"] == merged_id, f"association recorded merged {first['mergedApiId']!r}"

    expect_error(
        lambda: appsync.associate_source_graphql_api(
            mergedApiIdentifier=merged_id, sourceApiIdentifier=source_id
        ),
        *_DUPLICATE_ASSOCIATION,
    )

    summaries = appsync.list_source_api_associations(apiId=merged_id)["sourceApiAssociationSummaries"]
    assert [s["associationId"] for s in summaries] == [first_id], (
        f"expected only {first_id!r} listed after the refused duplicate, got {summaries!r}"
    )

    _disassociate(appsync, merged_id, first_id)
    _wait_until_removed(appsync, merged_id, first_id)

    empty = appsync.list_source_api_associations(apiId=merged_id)["sourceApiAssociationSummaries"]
    assert empty == [], f"expected no associations once {first_id!r} was removed, got {empty!r}"

    second = appsync.associate_source_graphql_api(
        mergedApiIdentifier=merged_id, sourceApiIdentifier=source_id
    )["sourceApiAssociation"]
    second_id = second["associationId"]
    ctx.on_cleanup(lambda: _disassociate(appsync, merged_id, second_id))
    assert second_id != first_id, f"re-association reused the removed id {first_id!r}"
    assert second["sourceApiId"] == source_id, f"re-association recorded source {second['sourceApiId']!r}"
    assert second["mergedApiId"] == merged_id, f"re-association recorded merged {second['mergedApiId']!r}"

    fetched = appsync.get_source_api_association(
        mergedApiIdentifier=merged_id, associationId=second_id
    )["sourceApiAssociation"]
    assert fetched["associationId"] == second_id, f"GetSourceApiAssociation returned {fetched['associationId']!r}"
    assert fetched["sourceApiId"] == source_id, f"GetSourceApiAssociation recorded source {fetched['sourceApiId']!r}"
    assert fetched["mergedApiId"] == merged_id, f"GetSourceApiAssociation recorded merged {fetched['mergedApiId']!r}"

    current = appsync.list_source_api_associations(apiId=merged_id)["sourceApiAssociationSummaries"]
    assert [s["associationId"] for s in current] == [second_id], (
        f"expected only the re-created {second_id!r} listed, got {current!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
