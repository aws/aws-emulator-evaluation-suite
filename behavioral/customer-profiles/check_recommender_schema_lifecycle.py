"""recommender-schema-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recommender-schema-lifecycle"
GROUP = "state"
SERVICES = ["customer-profiles"]

# The domain-level readiness refusal names `_webAnalytics` whichever dataset-type key the request
# carries.
_NO_DATA_TABLE = (
    "Unable to create recommender: Required data table for _webAnalytics is missing. Before "
    "creating a recommender, please ensure you have: 1. Ingested user interaction data (such as "
    "clicks, purchases, or views) and 2. Uploaded your product/item catalog data. The system will "
    "automatically create necessary tables when you import this data. Refer documentation for "
    "details: https://docs.aws.amazon.com/connect/latest/adminguide/predictive-insights-get-started.html"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRecommenderSchema for `_catalogItem` on a domain with no ingested source data fails with
    BadRequestException and the exact missing-data-table message, and GetRecommenderSchema then fails
    with ResourceNotFoundException "RecommenderSchema <name> is not found" while ListRecommenderSchemas omits it."""
    cp = ctx.client("customer-profiles")
    kms = ctx.client("kms")
    domain = ctx.unique_name("sim2real-cp-dom-")
    schema_name = ctx.unique_name("sim2real-cp-schema-")

    key_arn = kms.create_key(
        Description="sim2real-behav customer-profiles domain key",
        Tags=[{"TagKey": "sim2real", "TagValue": "recommender-schema-lifecycle"}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)))

    cp.create_domain(
        DomainName=domain,
        DefaultExpirationDays=30,
        DefaultEncryptionKey=key_arn,
        DataStore={"Enabled": True},
        Tags={"sim2real": "recommender-schema-lifecycle"},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    # No Predictive Insights source data has been ingested into this fresh domain, so the backing
    # data table the recommender schema would train against does not exist yet.
    code, message = _error(
        lambda: cp.create_recommender_schema(
            DomainName=domain,
            RecommenderSchemaName=schema_name,
            Fields={
                "_catalogItem": [
                    {"TargetFieldName": "Id", "ContentType": "STRING"},
                    {"TargetFieldName": "Name", "ContentType": "STRING"},
                ],
            },
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}: {message!r}"
    assert message == _NO_DATA_TABLE, f"expected the missing-backing-data-table message, got {message!r}"

    # effect absent: no schema was created by the rejected request.
    not_found_code, not_found_message = _error(
        lambda: cp.get_recommender_schema(DomainName=domain, RecommenderSchemaName=schema_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the refused schema, got {not_found_code!r}"
    )
    assert not_found_message == f"RecommenderSchema {schema_name} is not found", (
        f"unexpected GetRecommenderSchema message for the refused schema: {not_found_message!r}"
    )

    listed = cp.list_recommender_schemas(DomainName=domain)
    assert schema_name not in {i["RecommenderSchemaName"] for i in listed.get("Items", [])}


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

