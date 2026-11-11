"""update-ttl-attribute-name-exceeding-max-length-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-ttl-attribute-name-exceeding-max-length-rejected"
GROUP = "ttl"
SERVICES = ["dynamodb"]

_ENABLED_DEADLINE_S = 240.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTimeToLive with an AttributeName over 255 characters (client validation off) is
    rejected with ValidationException and its exact message, and TTL stays DISABLED; a
    255-character name is then accepted.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TimeToLiveSpecification.html
    """
    ddb = ctx.client("dynamodb")
    unvalidated_ddb = ctx.client("dynamodb", config=Config(parameter_validation=False))
    table = ctx.unique_name("sim2real-behav-ttlmax-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    too_long = "a" * 256
    rejected = False
    try:
        unvalidated_ddb.update_time_to_live(
            TableName=table,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": too_long},
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationException", f"expected ValidationException, got {code!r}"
        message = exc.response["Error"]["Message"]
        expected = (
            f"1 validation error detected: Value '{too_long}' at "
            f"'timeToLiveSpecification.attributeName' failed to satisfy constraint: Member must "
            f"have length less than or equal to 255"
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        rejected = True
    assert rejected, "a 256-character TTL AttributeName must be rejected, not silently accepted"

    disabled = ddb.describe_time_to_live(TableName=table)["TimeToLiveDescription"]
    assert disabled["TimeToLiveStatus"] == "DISABLED", (
        f"the refused UpdateTimeToLive changed TTL: {disabled!r}"
    )

    valid_name = "a" * 255
    ddb.update_time_to_live(
        TableName=table,
        TimeToLiveSpecification={"Enabled": True, "AttributeName": valid_name},
    )
    deadline = time.monotonic() + _ENABLED_DEADLINE_S
    while True:
        enabled = ddb.describe_time_to_live(TableName=table)["TimeToLiveDescription"]
        if enabled["TimeToLiveStatus"] == "ENABLED":
            break
        if time.monotonic() > deadline:
            raise AssertionError(
                f"TTL with a 255-character AttributeName did not reach ENABLED within "
                f"{_ENABLED_DEADLINE_S}s: {enabled!r}"
            )
        time.sleep(2.0)
    assert enabled.get("AttributeName") == valid_name, (
        f"expected the 255-character AttributeName stored, got {enabled!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
