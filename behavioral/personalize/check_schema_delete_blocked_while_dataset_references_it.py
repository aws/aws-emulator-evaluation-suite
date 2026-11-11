"""schema-delete-blocked-while-dataset-references-it."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-delete-blocked-while-dataset-references-it"
GROUP = "schema-lifecycle"
SERVICES = ["personalize"]

_INTERACTIONS_SCHEMA = json.dumps({
    "type": "record",
    "name": "Interactions",
    "namespace": "com.amazonaws.personalize.schema",
    "fields": [
        {"name": "USER_ID", "type": "string"},
        {"name": "ITEM_ID", "type": "string"},
        {"name": "TIMESTAMP", "type": "long"},
    ],
    "version": "1.0",
})


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s; last value={last!r}")


def _dataset_gone(p, dataset_arn: str) -> bool:
    try:
        p.describe_dataset(datasetArn=dataset_arn)
        return False
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A schema referenced by a dataset refuses DeleteSchema, and deleting the dataset
    first is what makes the schema deletable."""
    p = ctx.client("personalize")
    group_name = ctx.unique_name("sim2real-behav-personalize-dg-")
    schema_name = ctx.unique_name("sim2real-behav-personalize-sch-")
    dataset_name = ctx.unique_name("sim2real-behav-personalize-ds-")

    group_arn = p.create_dataset_group(name=group_name)["datasetGroupArn"]
    ctx.on_cleanup(_teardown(lambda: p.delete_dataset_group(datasetGroupArn=group_arn),
                              "ResourceNotFoundException"))

    _poll_until(
        lambda: p.describe_dataset_group(datasetGroupArn=group_arn)["datasetGroup"]["status"],
        lambda status: status == "ACTIVE",
        timeout_s=120, interval_s=5,
    )

    schema_arn = p.create_schema(name=schema_name, schema=_INTERACTIONS_SCHEMA)["schemaArn"]
    ctx.on_cleanup(_teardown(lambda: p.delete_schema(schemaArn=schema_arn),
                              "ResourceNotFoundException"))

    dataset_arn = p.create_dataset(
        name=dataset_name, datasetGroupArn=group_arn, schemaArn=schema_arn,
        datasetType="Interactions",
    )["datasetArn"]
    ctx.on_cleanup(_teardown(lambda: p.delete_dataset(datasetArn=dataset_arn),
                              "ResourceNotFoundException"))

    code, message = _error(lambda: p.delete_schema(schemaArn=schema_arn))
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}: {message!r}"
    expected_message = "The provided schema is being referenced by one or more datasets"
    assert message == expected_message, f"unexpected message {message!r}"

    p.delete_dataset(datasetArn=dataset_arn)
    _poll_until(
        lambda: _dataset_gone(p, dataset_arn),
        lambda gone: gone,
        timeout_s=120, interval_s=5,
    )

    # Positive control: with the dataset actually gone, the same delete now succeeds.
    p.delete_schema(schemaArn=schema_arn)
    code, message = _error(lambda: p.describe_schema(schemaArn=schema_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
