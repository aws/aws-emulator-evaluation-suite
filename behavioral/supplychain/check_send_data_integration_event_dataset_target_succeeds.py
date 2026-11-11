"""send-data-integration-event-dataset-target-succeeds."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-data-integration-event-dataset-target-succeeds"
GROUP = "data-plane"
SERVICES = ["supplychain"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendDataIntegrationEvent with a scn.data.dataset event matching the target dataset's schema is
    loaded asynchronously: GetDataIntegrationEvent reaches datasetLoadExecution status SUCCEEDED with
    the sent eventType and eventGroupId, and ListDataIntegrationEvents lists the event."""
    # AWS Supply Chain (CreateInstance) is region-pinned: real AWS answers ValidationException
    # ("Amazon Connect Decisions is not supported in ...") outside us-east-1.
    sc = ctx.client("supplychain", region="us-east-1")
    instance_id = _create_active_instance(ctx, sc)
    ns_name = _create_namespace(ctx, sc, instance_id)
    ds_name = _dl_name(ctx, "ds")

    schema = {
        "name": "SimEventSchema",
        "fields": [
            {"name": "id", "type": "STRING", "isRequired": True},
            {"name": "value", "type": "STRING", "isRequired": False},
        ],
        "primaryKeys": [{"name": "id"}],
    }
    dataset = sc.create_data_lake_dataset(
        instanceId=instance_id, namespace=ns_name, name=ds_name, schema=schema,
        tags={"sim2real:managed": "true"},
    )["dataset"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: sc.delete_data_lake_dataset(instanceId=instance_id, namespace=ns_name, name=ds_name)
        )
    )

    event_group_id = ctx.unique_name("sim2real-sc-evtgrp-")
    payload = json.dumps({"id": str(uuid.uuid4()), "value": "sim2real-hello"})
    sent = sc.send_data_integration_event(
        instanceId=instance_id,
        eventType="scn.data.dataset",
        eventGroupId=event_group_id,
        data=payload,
        datasetTarget={"datasetIdentifier": dataset["arn"], "operationType": "APPEND"},
    )
    event_id = sent["eventId"]

    final = _poll_until(
        lambda: sc.get_data_integration_event(instanceId=instance_id, eventId=event_id)["event"],
        lambda ev: ev["datasetTargetDetails"]["datasetLoadExecution"]["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    status = final["datasetTargetDetails"]["datasetLoadExecution"]["status"]
    assert status == "SUCCEEDED", f"dataset load did not succeed: {final}"
    assert final["eventType"] == "scn.data.dataset", f"expected eventType scn.data.dataset, got {final['eventType']!r}"
    assert final["eventGroupId"] == event_group_id, (
        f"expected eventGroupId {event_group_id!r}, got {final['eventGroupId']!r}"
    )

    found = _poll_until(
        lambda: {e["eventGroupId"] for e in sc.list_data_integration_events(instanceId=instance_id)["events"]},
        lambda ids: event_group_id in ids,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert event_group_id in found, f"expected {event_group_id!r} in ListDataIntegrationEvents, got {found!r}"


def _dl_name(ctx, kind):
    raw = ctx.unique_name(f"sim2real-sc-{kind}-")
    return raw.lower().replace("-", "").replace(".", "")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
        instanceName=name, instanceDescription="sim2real behavioral check",
        tags={"sim2real:managed": "true"},
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


def _create_namespace(ctx, sc, instance_id):
    ns_name = _dl_name(ctx, "ns")
    sc.create_data_lake_namespace(
        instanceId=instance_id, name=ns_name, description="sim2real namespace",
        tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sc.delete_data_lake_namespace(instanceId=instance_id, name=ns_name))
    )
    return ns_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
