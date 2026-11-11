"""start-schema-merge-without-source-association-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-schema-merge-without-source-association-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSchemaMerge on a valid Merged API with an unknown associationId returns
    NotFoundException, while a real associationId does not."""
    appsync = ctx.client("appsync")
    # A MERGED Api requires an execution role AppSync can assume to read/merge the source Apis'
    # schemas -- CreateGraphqlApi rejects apiType="MERGED" outright with a BadRequestException
    # ("Merged API execution role must be specified") without one.
    merge_role_arn = _create_merged_api_execution_role(ctx)
    merged_id = _create_merged_graphql_api(ctx, appsync, merge_role_arn)

    # A real associationId may be rejected for being mid-merge, but never as NotFoundException;
    # this makes the fake-id NotFoundException below specific to the id.
    source = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-source-"), authenticationType="API_KEY"
    )["graphqlApi"]
    source_id = source["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=source_id))
    real_association_id = appsync.associate_source_graphql_api(
        mergedApiIdentifier=merged_id, sourceApiIdentifier=source_id
    )["sourceApiAssociation"]["associationId"]
    def _disassociate():
        _safe(
            lambda: appsync.disassociate_source_graphql_api(
                mergedApiIdentifier=merged_id, associationId=real_association_id
            )
        )
        # Removal is async and DeleteGraphqlApi on the source refuses while it is associated.
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            summaries = appsync.list_source_api_associations(apiId=merged_id)[
                "sourceApiAssociationSummaries"
            ]
            if real_association_id not in [s["associationId"] for s in summaries]:
                return
            time.sleep(2)
        raise AssertionError(f"association {real_association_id} still listed after 60s")

    ctx.on_cleanup(_disassociate)
    try:
        appsync.start_schema_merge(
            associationId=real_association_id, mergedApiIdentifier=merged_id
        )
        positive_code = None
    except ClientError as exc:
        positive_code = exc.response["Error"]["Code"]
    assert positive_code != "NotFoundException", (
        f"StartSchemaMerge on a real associationId must not be NotFoundException, "
        f"got {positive_code!r}"
    )

    fake_association_id = str(uuid.uuid4())
    code, msg = _error(
        lambda: appsync.start_schema_merge(
            associationId=fake_association_id, mergedApiIdentifier=merged_id
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert msg == "No source API association was found", f"unexpected message: {msg!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_merged_graphql_api(ctx, appsync, merge_role_arn: str) -> str:
    """CreateGraphqlApi(apiType=MERGED), retrying the role rejection while the new role's trust
    policy propagates to AppSync (propagation time is unpredictable, so no fixed sleep)."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            resp = appsync.create_graphql_api(
                name=ctx.unique_name("sim2real-behav-merged-"),
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=merge_role_arn,
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = str(exc)
            role_not_ready = code in ("BadRequestException", "AccessDeniedException") and (
                "role" in message.lower() or "assume" in message.lower()
            )
            if role_not_ready and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    merged_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=merged_id))
    return merged_id


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

    _wait_for_role_readable(iam, role_name)
    return role_arn


def _wait_for_role_readable(iam, role_name, timeout_s: float = 30.0, interval_s: float = 3.0):
    """Bounded poll until IAM returns the new role; AppSync-side assumability is retried at
    CreateGraphqlApi instead."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"role {role_name} never became readable via get_role: {last_err}")


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
