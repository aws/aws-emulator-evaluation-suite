"""op-contract-disassociateSourceGraphqlApi."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-disassociateSourceGraphqlApi"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_TERMINAL_DELETION_STATES = {"DELETION_SCHEDULED", "DELETION_IN_PROGRESS", "DELETION_FAILED"}
_MERGE_PENDING_STATES = {"MERGE_SCHEDULED", "MERGE_IN_PROGRESS"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateSourceGraphqlApi refuses an unknown associationId with NotFoundException, moves a settled
    association to a deletion state until neither List nor GetSourceApiAssociation finds it, then refuses the
    removed id with NotFoundException and a malformed id with BadRequestException, each with its exact message."""
    appsync = ctx.client("appsync")
    source = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-src-"), authenticationType="API_KEY"
    )["graphqlApi"]
    source_id = source["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=source_id))

    # A MERGED Api requires an execution role AppSync can assume to read/merge the source
    # Apis' schemas -- CreateGraphqlApi rejects apiType="MERGED" outright with a
    # BadRequestException ("Merged API execution role must be specified") without one.
    merge_role_arn = _create_merged_api_execution_role(ctx)

    merged_id = _create_merged_graphql_api_with_retry(
        appsync, ctx.unique_name("sim2real-merged-"), merge_role_arn
    )
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=merged_id))

    assoc = appsync.associate_source_graphql_api(
        mergedApiIdentifier=merged_id,
        sourceApiIdentifier=source_id,
        description="sim2real behavioral association",
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]
    assert assoc["mergedApiId"] == merged_id
    assert assoc["sourceApiId"] == source_id

    def _cleanup_disassociate():
        from botocore.exceptions import ClientError

        try:
            appsync.disassociate_source_graphql_api(
                mergedApiIdentifier=merged_id, associationId=association_id
            )
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("NotFoundException", "BadRequestException"):
                raise

    ctx.on_cleanup(_cleanup_disassociate)

    # The association starts MERGE_SCHEDULED; DisassociateSourceGraphqlApi refuses with
    # ConcurrentModificationException until the merge attempt settles, so wait for it.
    def assoc_status():
        return appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"]

    settled = _poll_until(
        assoc_status, lambda s: s not in _MERGE_PENDING_STATES, timeout_s=120, interval_s=3
    )
    assert settled not in _MERGE_PENDING_STATES, f"association never settled: {settled}"

    # A well-formed associationId that names no association on this merged API is not found.
    unknown_code, unknown_msg = _error(
        lambda: appsync.disassociate_source_graphql_api(
            mergedApiIdentifier=merged_id, associationId=str(uuid.uuid4())
        )
    )
    assert unknown_code == "NotFoundException", f"expected NotFoundException, got {unknown_code}"
    assert unknown_msg == "No source API association was found", f"unexpected message: {unknown_msg!r}"

    resp = appsync.disassociate_source_graphql_api(
        mergedApiIdentifier=merged_id, associationId=association_id
    )
    assert resp["sourceApiAssociationStatus"] in _TERMINAL_DELETION_STATES, (
        f"unexpected status after disassociate: {resp['sourceApiAssociationStatus']}"
    )

    # Eventually the association should disappear from the merged API's list entirely.
    def probe():
        assocs = appsync.list_source_api_associations(apiId=merged_id).get(
            "sourceApiAssociationSummaries", []
        )
        return [a for a in assocs if a["associationId"] == association_id]

    remaining = _poll_until(probe, lambda res: len(res) == 0, timeout_s=120, interval_s=5)
    assert remaining == [], f"association still present after disassociate: {remaining}"

    def get_status():
        try:
            return assoc_status()
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return "REMOVED"
            raise

    removed = _poll_until(
        get_status,
        lambda s: s in ("REMOVED", "DELETION_FAILED"),
        timeout_s=min(150, ctx.time_left() or 150),
        interval_s=2,
    )
    assert removed == "REMOVED", f"GetSourceApiAssociation still finds the association, last status={removed}"

    # The removed identifier is dead: repeating the identical disassociate call that succeeded
    # earlier must not succeed again.
    dead_code, dead_msg = _error(
        lambda: appsync.disassociate_source_graphql_api(
            mergedApiIdentifier=merged_id, associationId=association_id
        )
    )
    assert dead_code == "NotFoundException", (
        f"expected NotFoundException disassociating an already-removed association, got {dead_code}"
    )
    assert dead_msg == "No source API association was found", f"unexpected message: {dead_msg!r}"

    # Error boundary: an associationId that is not UUID-shaped is refused at request validation
    # with BadRequestException, unlike the well-formed unknown id above, which is looked up and
    # reported missing with NotFoundException.
    code, msg = _error(
        lambda: appsync.disassociate_source_graphql_api(
            mergedApiIdentifier=merged_id, associationId="assoc-does-not-exist-1234"
        )
    )
    assert code == "BadRequestException", f"unexpected error code: {code}"
    assert msg == "Invalid SourceApi Association ID assoc-does-not-exist-1234", (
        f"unexpected message: {msg!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


def _create_merged_api_execution_role(ctx) -> str:
    """Create an IAM role AppSync can assume to merge source Apis into a Merged Api, and wait
    (bounded) for IAM's eventually-consistent role propagation so AppSync's own CreateGraphqlApi
    call doesn't reject the just-minted role as unassumable."""
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"][
        "Arn"
    ]
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

    _wait_for_role_visible(iam, role_name)
    return role_arn


def _wait_for_role_visible(iam, role_name, timeout_s: float = 30.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.get_role(RoleName=role_name)
            return
        except Exception:  # noqa: BLE001
            if time.monotonic() >= deadline:
                return
            time.sleep(interval_s)


def _create_merged_graphql_api_with_retry(
    appsync, name: str, role_arn: str, timeout_s: float = 60.0
) -> str:
    """A freshly-created IAM role isn't always immediately visible to AppSync (eventual
    consistency), so CreateGraphqlApi(apiType=MERGED) can transiently reject a just-minted
    mergedApiExecutionRoleArn; retry for a bounded window rather than failing on that race."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return appsync.create_graphql_api(
                name=name,
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
            )["graphqlApi"]["apiId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code == "BadRequestException" and "role" in message and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


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
