"""delete-graphql-api-source-of-merge-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-graphql-api-source-of-merge-rejected"
GROUP = "state-machine"
SERVICES = ["appsync"]

_MERGE_TERMINAL = {"MERGE_SUCCESS", "MERGE_FAILED"}


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=6.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last) and time.monotonic() < deadline:
        time.sleep(interval_s)
        last = probe()
    return last


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "NotFoundException"):
            raise


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _association_error(appsync, merged_api_id, association_id):
    """(code, message) once GetSourceApiAssociation refuses; the response while the association still reads."""
    try:
        return appsync.get_source_api_association(
            mergedApiIdentifier=merged_api_id, associationId=association_id
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGraphqlApi on a source API that is still associated with a merged API is
    rejected with BadRequestException and the source API is not deleted; after the
    association is removed (positive control) the same delete succeeds."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    source_api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-srcdel-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK},
    )["graphqlApi"]
    source_api_id, _source_api_arn = source_api["apiId"], source_api["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=source_api_id)))

    appsync.start_schema_creation(
        apiId=source_api_id, definition=b"type Query { hello: String }"
    )
    _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=source_api_id)["status"],
        lambda s: s != "PROCESSING",
        timeout_s=90.0,
        interval_s=5.0,
    )

    role_name = ctx.unique_name("sim2real-appsync-delrole-")
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
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="SourceGraphQLAccess"))
    )

    merged_api_id = None
    deadline = time.monotonic() + 30.0
    last_err = None
    while merged_api_id is None and time.monotonic() < deadline:
        try:
            merged_api_id = appsync.create_graphql_api(
                name=ctx.unique_name("sim2real-appsync-mergedel-"),
                authenticationType="API_KEY",
                apiType="MERGED",
                mergedApiExecutionRoleArn=role_arn,
                tags={"sim2real": CHECK},
            )["graphqlApi"]["apiId"]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] != "BadRequestException":
                raise
            time.sleep(3.0)
    if merged_api_id is None:
        raise AssertionError(f"could not create merged API: {last_err}")
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=merged_api_id)))

    association_id = appsync.associate_merged_graphql_api(
        sourceApiIdentifier=source_api_id, mergedApiIdentifier=merged_api_id
    )["sourceApiAssociation"]["associationId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: appsync.disassociate_merged_graphql_api(
                sourceApiIdentifier=source_api_id, associationId=association_id
            )
        )
    )

    final = _poll_until(
        lambda: appsync.get_source_api_association(
            mergedApiIdentifier=merged_api_id, associationId=association_id
        )["sourceApiAssociation"],
        lambda a: a["sourceApiAssociationStatus"] in _MERGE_TERMINAL,
        timeout_s=180.0,
        interval_s=6.0,
    )
    assert final["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"setup precondition not met: merge ended in {final['sourceApiAssociationStatus']}"
    )

    # Break exactly one precondition: try to delete the source API while it is still
    # associated with a merged API.
    err = _error(lambda: appsync.delete_graphql_api(apiId=source_api_id))
    assert err == (
        "BadRequestException",
        "API can not be deleted as it is associated to a Merged API",
    ), f"expected BadRequestException, got {err}"

    # The forbidden delete did not take effect.
    still_there = appsync.get_graphql_api(apiId=source_api_id)["graphqlApi"]
    assert still_there["apiId"] == source_api_id, (
        f"expected source api {source_api_id} to survive the rejected delete, "
        f"got {still_there.get('apiId')!r}"
    )

    # Positive control: once the association is removed, the identical delete succeeds.
    appsync.disassociate_merged_graphql_api(
        sourceApiIdentifier=source_api_id, associationId=association_id
    )
    disassociated_err = _poll_until(
        lambda: _association_error(appsync, merged_api_id, association_id),
        lambda err: isinstance(err, tuple),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert disassociated_err == ("NotFoundException", "No source API association was found"), (
        f"expected association {association_id} to disappear after disassociation, "
        f"got {disassociated_err!r}"
    )

    appsync.delete_graphql_api(apiId=source_api_id)
    final_err = _error(lambda: appsync.get_graphql_api(apiId=source_api_id))
    assert final_err == ("NotFoundException", "API not found."), (
        f"expected source api {source_api_id} to be gone after the restored delete, "
        f"got {final_err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
