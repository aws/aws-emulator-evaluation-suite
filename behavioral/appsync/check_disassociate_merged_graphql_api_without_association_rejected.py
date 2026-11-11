"""disassociate-merged-graphql-api-without-association-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-merged-graphql-api-without-association-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_TERMINAL = {"MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateMergedGraphqlApi with an associationId that never existed for a valid source Api
    fails NotFoundException, after a real association on the same source was disassociated."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    source = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"), authenticationType="API_KEY"
    )["graphqlApi"]
    api_id, source_arn = source["apiId"], source["arn"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    merge_role_arn = _create_merge_execution_role(ctx, iam, source_arn)
    merged_id = _create_merged_graphql_api(ctx, appsync, merge_role_arn)

    assoc = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=api_id, mergedApiIdentifier=merged_id
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]
    ctx.on_cleanup(lambda: _safe_disassociate(appsync, api_id, association_id))

    status = _poll_merge_terminal(appsync, merged_id, association_id, timeout_s=180, interval_s=5)
    assert status in _TERMINAL, f"merge did not reach a terminal status within 180s (still {status!r})"

    # Positive control: the real association disassociates cleanly on this exact
    # sourceApiIdentifier, proving the operation and these credentials both work.
    appsync.disassociate_merged_graphql_api(sourceApiIdentifier=api_id, associationId=association_id)
    removed = _poll_until(
        lambda: _list_association_ids(appsync, api_id),
        lambda ids: association_id not in ids,
        timeout_s=120,
        interval_s=5,
    )
    assert removed, "positive-control DisassociateMergedGraphqlApi never removed the association"

    # Break exactly one thing: ask about an associationId that was never real, on the very
    # sourceApiIdentifier that just proved the operation works.
    fake_association_id = str(uuid.uuid4())
    err = _error(
        lambda: appsync.disassociate_merged_graphql_api(
            sourceApiIdentifier=api_id, associationId=fake_association_id
        )
    )
    assert err == ("NotFoundException", "No source API association was found"), (
        f"expected NotFoundException, got {err!r}"
    )

    # Independent read, through a different operation than the rejected call: the rejection had
    # no side effect -- the source Api still has no association at all.
    remaining = _list_association_ids(appsync, api_id)
    assert remaining == set(), f"expected no associations after a rejected disassociate, got {remaining}"


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return True
        time.sleep(interval_s)
        result = probe()
    return predicate(result)


def _poll_merge_terminal(appsync, merged_id: str, association_id: str, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    return status


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


def _safe_disassociate(appsync, source_api_id: str, association_id: str) -> None:
    try:
        appsync.disassociate_merged_graphql_api(
            sourceApiIdentifier=source_api_id, associationId=association_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_merge_execution_role(ctx, iam, source_api_arn: str) -> str:
    """A MERGED Api requires an execution role AppSync can assume to read/merge the source Apis'
    schemas -- CreateGraphqlApi rejects apiType="MERGED" outright without one. A freshly-created
    role is not immediately assumable everywhere (IAM's eventual-consistency window), which
    _create_merged_graphql_api below retries around."""
    role_name = ctx.unique_name("sim2real-behav-mergerole-")[:64]
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"][
        "Arn"
    ]
    ctx.on_cleanup(lambda: _delete_role_quiet(iam, role_name))

    policy_name = "sim2real-behav-merge-policy"
    policy_doc = json.dumps(
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
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: _delete_role_policy_quiet(iam, role_name, policy_name))
    return role_arn


def _create_merged_graphql_api(ctx, appsync, merge_role_arn: str) -> str:
    deadline = time.monotonic() + 30
    name = ctx.unique_name("sim2real-behav-merged-")
    while True:
        try:
            api_id = appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=merge_role_arn,
            )["graphqlApi"]["apiId"]
            ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
            return api_id
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
