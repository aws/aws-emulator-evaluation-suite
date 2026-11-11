"""get-action-recommendations-wrong-resource-type-arn-not-found."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-action-recommendations-wrong-resource-type-arn-not-found"
GROUP = "overly-permissive"
SERVICES = ["personalize-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetActionRecommendations with an existing schema's ARN as campaignArn gets InvalidInputException
    "The given campaign ARN is invalid: <arn>", while a fabricated campaign ARN gets the exact does-not-
    exist InvalidInputException."""
    personalize = ctx.client("personalize")
    rt = ctx.client("personalize-runtime")
    user_id = ctx.unique_name("user-")

    schema = {
        "type": "record",
        "name": "Interactions",
        "namespace": "com.amazonaws.personalize.schema",
        "fields": [
            {"name": "USER_ID", "type": "string"},
            {"name": "ITEM_ID", "type": "string"},
            {"name": "TIMESTAMP", "type": "long"},
        ],
        "version": "1.0",
    }
    schema_name = ctx.unique_name("sim2real-personalize-schema-")
    schema_arn = personalize.create_schema(name=schema_name, schema=json.dumps(schema))["schemaArn"]
    ctx.on_cleanup(lambda: _safe_delete_schema(personalize, schema_arn))

    described = personalize.describe_schema(schemaArn=schema_arn)["schema"]
    assert described["schemaArn"] == schema_arn, (
        f"expected describe_schema to echo back {schema_arn!r}, got {described['schemaArn']!r}"
    )

    err = _error(lambda: rt.get_action_recommendations(campaignArn=schema_arn, userId=user_id))
    assert err["Code"] == "InvalidInputException", f"expected InvalidInputException, got {err!r}"
    assert err["Message"] == f"The given campaign ARN is invalid: {schema_arn}", (
        f"unexpected wrong-type message {err['Message']!r}"
    )

    # positive control: a fabricated (nonexistent) campaign ARN takes the exact same code path.
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    fabricated_arn = (
        f"arn:aws:personalize:{ctx.region}:{account_id}:campaign/"
        f"{ctx.unique_name('sim2real-personalize-nope-')}"
    )
    err2 = _error(lambda: rt.get_action_recommendations(campaignArn=fabricated_arn, userId=user_id))
    assert err2["Code"] == "InvalidInputException", f"expected InvalidInputException, got {err2!r}"
    assert err2["Message"] == f"{fabricated_arn} does not exist or is not active yet.", (
        f"unexpected nonexistent-campaign message {err2['Message']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict ({"Code", "Message", ...}). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete_schema(personalize, schema_arn):
    try:
        personalize.delete_schema(schemaArn=schema_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
