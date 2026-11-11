"""send-event-dataset-target-missing-ref-not-found."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-event-dataset-target-missing-ref-not-found"
GROUP = "error-semantics"
SERVICES = ["supplychain"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendDataIntegrationEvent targeting a dataset that does not exist fails with
    ResourceNotFoundException and the exact message and records no event; once the dataset exists the
    same event is accepted and GetDataIntegrationEvent reports its load SUCCEEDED."""
    # AWS Supply Chain (CreateInstance) is region-pinned: real AWS answers ValidationException
    # ("Amazon Connect Decisions is not supported in ...") outside us-east-1.
    sc = ctx.client("supplychain", region="us-east-1")
    instance_id = _create_active_instance(ctx, sc)
    ns_name = _create_namespace(ctx, sc, instance_id)
    ds_name = _dl_name(ctx, "ds")

    region = sc.meta.region_name
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    missing_dataset_arn = f"arn:aws:scn:{region}:{account_id}:instance/{instance_id}/namespaces/{ns_name}/datasets/{ds_name}"

    event_group_id = ctx.unique_name("sim2real-sc-evtgrp-")
    payload = json.dumps({"id": str(uuid.uuid4())})

    # (a) the specific error code, while the dataset does not exist yet
    code, message = _error(
        lambda: sc.send_data_integration_event(
            instanceId=instance_id,
            eventType="scn.data.dataset",
            eventGroupId=event_group_id,
            data=payload,
            datasetTarget={"datasetIdentifier": missing_dataset_arn, "operationType": "APPEND"},
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Target dataset resource arn: {missing_dataset_arn} is not valid"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # (b) the effect is absent: no events were recorded for this eventGroupId
    events_before = {e["eventGroupId"] for e in sc.list_data_integration_events(instanceId=instance_id)["events"]}
    assert event_group_id not in events_before, (
        f"expected {event_group_id!r} absent from ListDataIntegrationEvents before the dataset "
        f"existed, found it in {events_before!r}"
    )

    # (c) positive control: once the referenced dataset exists, the identical send succeeds
    schema = {"name": "SimSchema", "fields": [{"name": "id", "type": "STRING", "isRequired": True}]}
    created = sc.create_data_lake_dataset(
        instanceId=instance_id, namespace=ns_name, name=ds_name, schema=schema,
        tags={"sim2real:managed": "true"},
    )["dataset"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: sc.delete_data_lake_dataset(instanceId=instance_id, namespace=ns_name, name=ds_name)
        )
    )
    assert created["arn"] == missing_dataset_arn, (
        f"constructed ARN did not match the real dataset ARN: expected {missing_dataset_arn!r}, "
        f"got {created['arn']!r}"
    )

    sent = sc.send_data_integration_event(
        instanceId=instance_id,
        eventType="scn.data.dataset",
        eventGroupId=event_group_id,
        data=payload,
        datasetTarget={"datasetIdentifier": missing_dataset_arn, "operationType": "APPEND"},
    )
    assert sent["eventId"], f"expected a non-empty eventId, got {sent.get('eventId')!r}"

    # (d) independent terminal read at the destination: GetDataIntegrationEvent, a different
    # operation than the one that sent the event, confirms it was actually loaded into the
    # now-existing dataset rather than merely accepted.
    final = _poll_until(
        lambda: sc.get_data_integration_event(instanceId=instance_id, eventId=sent["eventId"])["event"],
        lambda ev: ev["datasetTargetDetails"]["datasetLoadExecution"]["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    status = final["datasetTargetDetails"]["datasetLoadExecution"]["status"]
    assert status == "SUCCEEDED", f"expected dataset load SUCCEEDED, got {status!r}: {final}"
    assert final["eventGroupId"] == event_group_id, (
        f"expected eventGroupId {event_group_id!r} on the independent read, got {final['eventGroupId']!r}"
    )


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
