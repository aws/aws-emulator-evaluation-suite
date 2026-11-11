"""delete-namespace-with-dataset-conflict-then-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-namespace-with-dataset-conflict-then-succeeds"
GROUP = "error-semantics"
SERVICES = ["supplychain"]

# AWS Supply Chain (service prefix "scn") is not available in every region; real AWS rejects
# CreateInstance in us-west-2 with ValidationException "Amazon Connect Decisions is not supported
# in us-west-2". us-east-1 is where the service launched and remains supported.
_SC_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDataLakeNamespace is rejected with ValidationException naming the namespace while it
    still contains a dataset; the namespace remains intact, and deleting it succeeds once the
    dataset is gone."""
    sc = ctx.client("supplychain", region=_SC_REGION)
    instance_id = _create_active_instance(ctx, sc)
    ns_name = _dl_name(ctx, "ns")
    ds_name = _dl_name(ctx, "ds")

    sc.create_data_lake_namespace(
        instanceId=instance_id, name=ns_name, description="sim2real namespace", tags={"team": "sim2real"}
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sc.delete_data_lake_namespace(instanceId=instance_id, name=ns_name))
    )
    schema = {"name": "SimSchema", "fields": [{"name": "id", "type": "STRING", "isRequired": True}]}
    sc.create_data_lake_dataset(
        instanceId=instance_id, namespace=ns_name, name=ds_name, schema=schema, tags={"team": "sim2real"}
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: sc.delete_data_lake_dataset(instanceId=instance_id, namespace=ns_name, name=ds_name)
        )
    )

    # (a) the specific error code, with a message tight enough to name the actual blocker (the
    # namespace still holding a dataset) rather than any other ValidationException
    code, message = _error(lambda: sc.delete_data_lake_namespace(instanceId=instance_id, name=ns_name))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = f"Datasets found under the namespace {ns_name}. Please delete them before deleting the namespace"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # (b) the effect is absent: the namespace still exists
    still_there = sc.get_data_lake_namespace(instanceId=instance_id, name=ns_name)["namespace"]
    assert still_there["name"] == ns_name, f"expected namespace {ns_name} to survive the conflict, got {still_there!r}"

    # (c) positive control: once the dataset is removed, deletion succeeds
    sc.delete_data_lake_dataset(instanceId=instance_id, namespace=ns_name, name=ds_name)
    sc.delete_data_lake_namespace(instanceId=instance_id, name=ns_name)
    gone_message = f"Namespace {ns_name} not exist"
    code_after, message_after = _error(lambda: sc.get_data_lake_namespace(instanceId=instance_id, name=ns_name))
    assert code_after == "ResourceNotFoundException", f"expected namespace gone, got {code_after}"
    assert message_after == gone_message, f"expected {gone_message!r}, got {message_after!r}"

    # (d) the dead id is also unusable: a repeat delete on the now-gone namespace fails the same way
    code_redelete, message_redelete = _error(lambda: sc.delete_data_lake_namespace(instanceId=instance_id, name=ns_name))
    assert code_redelete == "ResourceNotFoundException", f"expected repeat delete to see namespace gone, got {code_redelete}"
    assert message_redelete == gone_message, f"expected {gone_message!r}, got {message_redelete!r}"


def _dl_name(ctx, kind):
    raw = ctx.unique_name(f"sim2real-sc-{kind}-")
    return raw.lower().replace("-", "").replace(".", "")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name, instanceDescription="sim2real behavioral check", tags={"team": "sim2real"}
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        try:
            sc.delete_instance(instanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    result = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if result["state"] != "Active":
        raise AssertionError(f"instance did not reach Active state: {result}")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
