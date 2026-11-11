"""get-schema-status-and-association-not-found."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "get-schema-status-and-association-not-found"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSchemaCreationStatus, GetSourceApiAssociation and GetDataSourceIntrospection fail
    NotFoundException for missing targets; StartDataSourceIntrospection on a nonexistent RDS target
    is accepted and ends FAILED."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY"
    )["graphqlApi"]
    api_id = api["apiId"]

    pre_delete = svc.get_schema_creation_status(apiId=api_id)
    assert "status" in pre_delete, (
        f"GetSchemaCreationStatus on the live api {api_id!r} returned no status: {pre_delete!r}"
    )

    svc.delete_graphql_api(apiId=api_id)

    code, message = _error(lambda: svc.get_schema_creation_status(apiId=api_id))
    assert code == "NotFoundException", f"GetSchemaCreationStatus: expected NotFoundException, got {code}"
    assert message == "API not found.", f"GetSchemaCreationStatus: unexpected message {message!r}"

    code, message = _error(
        lambda: svc.get_source_api_association(
            mergedApiIdentifier=api_id, associationId=str(uuid.uuid4())
        )
    )
    assert code == "NotFoundException", f"GetSourceApiAssociation: expected NotFoundException, got {code}"
    assert message == "API not found.", f"GetSourceApiAssociation: unexpected message {message!r}"

    code, message = _error(
        lambda: svc.get_data_source_introspection(introspectionId=str(uuid.uuid4()))
    )
    assert code == "NotFoundException", f"GetDataSourceIntrospection: expected NotFoundException, got {code}"
    assert message == "No introspection was found that matches the supplied ID.", (
        f"GetDataSourceIntrospection: unexpected message {message!r}"
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    start_resp = svc.start_data_source_introspection(
        rdsDataApiConfig={
            "resourceArn": f"arn:aws:rds:{ctx.region}:{account_id}:cluster:sim2real-behav-nonexistent",
            "secretArn": (
                f"arn:aws:secretsmanager:{ctx.region}:{account_id}:secret:sim2real-behav-nonexistent"
            ),
            "databaseName": "mydb",
        }
    )
    # StartDataSourceIntrospection does NOT synchronously validate that the referenced RDS
    # cluster/secret exist — it accepts the request and surfaces the failure asynchronously.
    introspection_id = start_resp["introspectionId"]
    final = _poll_until(
        lambda: svc.get_data_source_introspection(introspectionId=introspection_id),
        lambda r: r["introspectionStatus"] in ("SUCCESS", "FAILED"),
        timeout_s=60,
        interval_s=3.0,
        description="data source introspection against a nonexistent RDS cluster to reach a terminal state",
    )
    assert final["introspectionStatus"] == "FAILED", (
        f"expected introspection of a nonexistent RDS cluster/secret to reach FAILED, "
        f"got {final['introspectionStatus']!r}"
    )
    detail = final.get("introspectionStatusDetail")
    assert detail == "RDS cluster was not found for supplied resource arn.", (
        f"unexpected introspectionStatusDetail for the FAILED introspection: {detail!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
