"""associate-merged-graphql-api-invalid-source-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-merged-graphql-api-invalid-source-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateMergedGraphqlApi naming a nonexistent sourceApiIdentifier fails BadRequestException
    with no dangling association, while a real source Api is accepted by the same Merged Api."""
    appsync = ctx.client("appsync")
    # A MERGED Api requires an execution role AppSync can assume to read/merge the source Apis'
    # schemas -- CreateGraphqlApi rejects apiType="MERGED" outright with a BadRequestException
    # ("Merged API execution role must be specified") without one.
    merge_role_arn = _create_merged_api_execution_role(ctx)
    merged_id = _create_merged_graphql_api_with_retry(appsync, ctx, merge_role_arn)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_graphql_api(apiId=merged_id)))

    source_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-source-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_graphql_api(apiId=source_id)))

    # Positive control: a real source Api is accepted by the same Merged Api. Without this, a
    # target that rejects every AssociateMergedGraphqlApi call (or one that never delivers on
    # this merged role) would pass the negative below for the wrong reason.
    control = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=source_id, mergedApiIdentifier=merged_id
    )["sourceApiAssociation"]
    control_id = control["associationId"]
    assert control["sourceApiId"] == source_id, control
    assert control["mergedApiId"] == merged_id, control
    ctx.on_cleanup(lambda: _safe_disassociate(appsync, source_id, merged_id, control_id))

    fake_source_id = uuid.uuid4().hex[:26]
    code, message = _error(
        lambda: appsync.associate_merged_graphql_api(
            sourceApiIdentifier=fake_source_id, mergedApiIdentifier=merged_id
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == f"Invalid API ID {fake_source_id}", (
        f"expected AWS's exact invalid-source message naming {fake_source_id!r}, got {message!r}"
    )

    # No dangling association for the fake source: the merged Api's only association is still
    # the positive control's, read independently via list rather than either mutating call.
    associations = appsync.list_source_api_associations(apiId=merged_id)[
        "sourceApiAssociationSummaries"
    ]
    ids = [a["associationId"] for a in associations]
    assert ids == [control_id], f"expected only the control association {control_id!r}, found {ids}"


def _error(fn):
    """Call fn(); return its botocore error (code, message).
    An unexpected success raises: accepting what AWS refuses is a finding, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _ignore_no_such_entity(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_merged_api_execution_role(ctx) -> str:
    """Create an IAM role AppSync can assume to merge source Apis into a Merged Api."""
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
            "Statement": [{"Effect": "Allow", "Action": "appsync:SourceGraphQLAPI", "Resource": "*"}],
        }
    )
    policy_name = "sim2real-appsync-merge-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: _delete_role_policy_quiet(iam, role_name, policy_name))
    return role_arn


def _create_merged_graphql_api_with_retry(appsync, ctx, role_arn: str, timeout_s: float = 60.0) -> str:
    """A freshly-minted IAM role isn't always immediately visible to AppSync (eventual
    consistency), so CreateGraphqlApi(apiType=MERGED) can transiently reject a just-minted
    mergedApiExecutionRoleArn -- retry for a bounded window keyed on that specific rejection
    rather than sleeping blind before the first attempt."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return appsync.create_graphql_api(
                name=ctx.unique_name("sim2real-behav-merged-"),
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )["graphqlApi"]["apiId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "").lower()
            if code == "BadRequestException" and "role" in message and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _safe_disassociate(appsync, source_api_id: str, merged_api_id: str, association_id: str) -> None:
    """Disassociate, then wait for the association to actually be gone. Disassociation runs
    through a DELETION_IN_PROGRESS state rather than completing inline with the API response --
    deleting the source or merged Api immediately afterwards can still be rejected with
    BadRequestException ("still associated"), and a swallowed cleanup exception would leave that
    Api behind."""
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            appsync.disassociate_merged_graphql_api(
                sourceApiIdentifier=source_api_id, associationId=association_id
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "ConcurrentModificationException":
                time.sleep(10)
                continue
            raise
    else:
        return

    while time.monotonic() < deadline:
        try:
            appsync.get_source_api_association(
                mergedApiIdentifier=merged_api_id, associationId=association_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(5)


def _delete_role_quiet(iam, role_name: str) -> None:
    _ignore_no_such_entity(lambda: iam.delete_role(RoleName=role_name))


def _delete_role_policy_quiet(iam, role_name: str, policy_name: str) -> None:
    _ignore_no_such_entity(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
