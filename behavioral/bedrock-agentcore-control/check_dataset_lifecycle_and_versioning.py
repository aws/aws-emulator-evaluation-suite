"""dataset-lifecycle-and-versioning."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dataset-lifecycle-and-versioning"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataset converges CREATING -> ACTIVE, AddDatasetExamples grows the editable working
    version's example count, and CreateDatasetVersion publishes a numbered, immutable version while
    the working version stays independently editable."""
    control = ctx.client("bedrock-agentcore-control")

    dataset_name = _no_hyphen_name(ctx, "sim2realdataset")
    create_resp = control.create_dataset(
        datasetName=dataset_name,
        schemaType="AGENTCORE_EVALUATION_PREDEFINED_V1",
        source={
            "inlineExamples": {
                "examples": [
                    {
                        "scenario_id": "sim2real-TC-01",
                        "turns": [{"input": "What is my balance?"}],
                    }
                ]
            }
        },
    )
    dataset_id = create_resp["datasetId"]
    ctx.on_cleanup(
        lambda: _delete_dataset_best_effort(control, dataset_id)
    )
    assert create_resp["status"] == "CREATING"

    active = _poll_until(
        lambda: control.get_dataset(datasetId=dataset_id),
        lambda d: d["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert active["status"] == "ACTIVE", f"dataset ended in {active['status']!r}"

    add_resp = control.add_dataset_examples(
        datasetId=dataset_id,
        source={
            "inlineExamples": {
                "examples": [
                    {
                        "scenario_id": "sim2real-TC-02",
                        "turns": [{"input": "Transfer 100 dollars"}],
                    }
                ]
            }
        },
    )
    assert add_resp["addedCount"] == 1
    assert len(add_resp["exampleIds"]) == 1

    # AddDatasetExamples can itself transition the dataset through UPDATING;
    # wait for it to settle before publishing a version.
    _poll_until(
        lambda: control.get_dataset(datasetId=dataset_id),
        lambda d: d["status"] in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=120,
        interval_s=3,
    )

    version_resp = control.create_dataset_version(datasetId=dataset_id)
    assert version_resp["datasetVersion"] == "1"
    assert version_resp["status"] == "UPDATING"

    updated = _poll_until(
        lambda: control.get_dataset(datasetId=dataset_id),
        lambda d: d["status"] in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert updated["status"] == "ACTIVE", f"version publish ended in {updated['status']!r}"

    # the DRAFT remains editable and independent of the published version: capture what
    # version 1 froze at, and the DRAFT's own count, on independent reads before touching
    # either again.
    frozen_versions = control.list_dataset_versions(datasetId=dataset_id)["versions"]
    assert len(frozen_versions) == 1
    frozen_example_count = frozen_versions[0]["exampleCount"]
    draft_count_before = control.get_dataset(datasetId=dataset_id)["exampleCount"]

    add_resp_2 = control.add_dataset_examples(
        datasetId=dataset_id,
        source={
            "inlineExamples": {
                "examples": [
                    {
                        "scenario_id": "sim2real-TC-03",
                        "turns": [{"input": "Close my account"}],
                    }
                ]
            }
        },
    )
    assert add_resp_2["addedCount"] == 1

    # AddDatasetExamples transitions the dataset through UPDATING again; the DRAFT's
    # reported exampleCount does not reflect the addition until it settles back to ACTIVE.
    _poll_until(
        lambda: control.get_dataset(datasetId=dataset_id),
        lambda d: d["status"] in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=120,
        interval_s=3,
    )

    # independent reads, through different operations than the mutation above: the DRAFT
    # grew by exactly the addition, and the already-published version 1 stayed frozen.
    draft_after = control.get_dataset(datasetId=dataset_id)
    assert draft_after["exampleCount"] == draft_count_before + 1, (
        f"DRAFT exampleCount should grow by 1: before={draft_count_before} "
        f"after={draft_after['exampleCount']}"
    )
    versions_after = control.list_dataset_versions(datasetId=dataset_id)["versions"]
    assert len(versions_after) == 1
    assert versions_after[0]["exampleCount"] == frozen_example_count, (
        "published version 1 must stay frozen even though the DRAFT grew: "
        f"frozen={frozen_example_count} now={versions_after[0]['exampleCount']}"
    )

    # deletes prove gone and unusable: an independent read reports the specific not-found
    # code, and a mutation against the dead id fails the same way.
    control.delete_dataset(datasetId=dataset_id)
    code, message = _error(
        lambda: control.get_dataset(datasetId=dataset_id), timeout_s=120, interval_s=3
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    not_found = "The specified dataset does not exist. Please verify the datasetId and try again."
    assert message == not_found, f"expected {not_found!r}, got {message!r}"

    mutate_code, mutate_message = _error(
        lambda: control.add_dataset_examples(
            datasetId=dataset_id,
            source={"inlineExamples": {"examples": [{"scenario_id": "sim2real-TC-04", "turns": [{"input": "post-delete"}]}]}},
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"mutation on a deleted dataset should fail not-found, got {mutate_code!r}"
    )
    assert mutate_message == not_found, f"expected {not_found!r}, got {mutate_message!r}"


def _error(fn, *, timeout_s=0.0, interval_s=3.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    succeeds once timeout_s has passed raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError("expected the call to be refused, but it succeeded")
        time.sleep(interval_s)


def _no_hyphen_name(ctx, prefix):
    raw = ctx.unique_name(f"{prefix}-")
    sanitized = "".join(ch for ch in raw if ch.isalnum() or ch == "_")
    return sanitized[:40]


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_dataset_best_effort(control, dataset_id):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            control.delete_dataset(datasetId=dataset_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            time.sleep(5)
    control.delete_dataset(datasetId=dataset_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

