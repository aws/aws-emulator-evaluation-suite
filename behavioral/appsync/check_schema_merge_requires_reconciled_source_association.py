"""schema-merge-requires-reconciled-source-association."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-merge-requires-reconciled-source-association"
GROUP = "ordering"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSchemaMerge on an association whose initial merge is still running is rejected with
    ConcurrentModificationException; once the association is terminal, a new merge is accepted
    and runs to a terminal status."""
    appsync = ctx.client("appsync")
    # A MERGED Api requires an execution role AppSync can assume to read/merge the source Apis'
    # schemas -- CreateGraphqlApi rejects apiType="MERGED" outright with a BadRequestException
    # ("Merged API execution role must be specified") without one.
    merge_role_arn = _create_merged_api_execution_role(ctx)
    merged = _create_merged_api_with_retry(appsync, ctx, merge_role_arn)
    merged_id = merged["apiId"]
    source = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-source-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    source_id = source["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=merged_id))
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=source_id))

    # A schema-less source's initial merge fails within one round trip, leaving no in-progress
    # window to observe; a real schema makes the initial merge take measurable time.
    _create_and_activate_schema(appsync, source_id)

    assoc = appsync.associate_source_graphql_api(
        mergedApiIdentifier=merged_id, sourceApiIdentifier=source_id
    )["sourceApiAssociation"]
    association_id = assoc["associationId"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(appsync, merged_id, association_id))

    terminal_statuses = ("MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED")

    status_now = appsync.get_source_api_association(
        mergedApiIdentifier=merged_id, associationId=association_id
    )["sourceApiAssociation"]["sourceApiAssociationStatus"]
    if status_now not in terminal_statuses:
        # AppSync reports an in-flight initial merge like any in-progress merge, with
        # ConcurrentModificationException, for the whole non-terminal window.
        code, message = _error(
            lambda: appsync.start_schema_merge(
                associationId=association_id, mergedApiIdentifier=merged_id
            )
        )
        assert code == "ConcurrentModificationException", (
            f"expected ConcurrentModificationException while unreconciled, got {code!r}"
        )
        assert message == (
            "This association currently has an operation in progress, please wait until that is complete"
        ), f"unexpected ConcurrentModificationException message {message!r}"

    terminal = _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"],
        lambda status: status in terminal_statuses,
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert terminal in terminal_statuses, (
        f"source association never reconciled, stuck at {terminal!r}"
    )

    # Once reconciled, StartSchemaMerge is accepted and schedules a new merge cycle.
    result = appsync.start_schema_merge(
        associationId=association_id, mergedApiIdentifier=merged_id
    )
    assert result["sourceApiAssociationStatus"] in (
        "MERGE_SCHEDULED",
        "MERGE_IN_PROGRESS",
        "MERGE_SUCCESS",
    ), f"unexpected post-reconciliation merge status {result['sourceApiAssociationStatus']!r}"

    # The StartSchemaMerge response is not the verdict; confirm the merge reaches a terminal state.
    reconfirmed = _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"]["sourceApiAssociationStatus"],
        lambda status: status in terminal_statuses,
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert reconfirmed in terminal_statuses, (
        f"the re-triggered merge never independently reached a terminal status, "
        f"stuck at {reconfirmed!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


def _disassociate_and_wait(appsync, merged_id: str, association_id: str, timeout_s: float = 180.0) -> None:
    """Disassociation is asynchronous; neither API can be deleted until the association is gone."""
    appsync.disassociate_source_graphql_api(mergedApiIdentifier=merged_id, associationId=association_id)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            appsync.get_source_api_association(mergedApiIdentifier=merged_id, associationId=association_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3.0)
    raise AssertionError(f"source api association {association_id} still present {timeout_s}s after disassociation")


def _create_and_activate_schema(appsync, api_id: str) -> None:
    definition = b"schema { query: Query }\ntype Query { ping: String }\n"
    appsync.start_schema_creation(apiId=api_id, definition=definition)
    status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id)["status"],
        lambda s: s in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert status in ("SUCCESS", "ACTIVE"), f"source API schema creation failed: {status!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_merged_api_with_retry(appsync, ctx, merge_role_arn: str, timeout_s: float = 90.0):
    """Create the MERGED api, retrying the role rejection while the new role's trust policy
    propagates to AppSync (eventually consistent, so no fixed sleep can be right)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return appsync.create_graphql_api(
                name=ctx.unique_name("sim2real-behav-merged-"),
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=merge_role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )["graphqlApi"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc)
            if code == "BadRequestException" and "role" in msg.lower():
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        f"merge execution role never became assumable within {timeout_s}s: {exc}"
                    ) from exc
                time.sleep(3.0)
                continue
            raise


def _create_merged_api_execution_role(ctx) -> str:
    """Create an IAM role AppSync can assume to merge source Apis, waiting (bounded) for IAM to
    return it from GetRole."""
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

    _wait_for_role_assumable(iam, role_name)
    return role_arn


def _wait_for_role_assumable(iam, role_name, timeout_s: float = 30.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:  # noqa: BLE001
            if time.monotonic() >= deadline:
                break
            time.sleep(interval_s)
    # GetRole only proves the role exists; AppSync-side propagation is retried at first use.


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
