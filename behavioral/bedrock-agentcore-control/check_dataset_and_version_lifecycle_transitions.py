"""dataset-and-version-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dataset-and-version-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Dataset create->ACTIVE, CreateDatasetVersion adds to version history
    without orphaning it, UpdateDataset persists while ACTIVE, and
    DeleteDataset cascades so GetDataset returns ResourceNotFoundException."""
    bac = ctx.client("bedrock-agentcore-control")
    name = _safe_name(ctx, "sim2realds")

    create_resp = bac.create_dataset(
        datasetName=name,
        source={
            "inlineExamples": {
                "examples": [
                    {"scenario_id": "sim2real-scenario-1", "turns": [{"input": "hello"}]}
                ]
            }
        },
        schemaType="AGENTCORE_EVALUATION_PREDEFINED_V1",
        tags={"env": "sim2real-test", "purpose": "dataset-and-version-lifecycle-transitions"},
    )
    dataset_id = create_resp["datasetId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: bac.delete_dataset(datasetId=dataset_id)))

    ds = _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )
    assert ds["status"] == "ACTIVE", f"unexpected terminal status {ds['status']!r}"
    assert ds["exampleCount"] == 1, f"expected 1 seeded example, got {ds['exampleCount']!r}"

    bac.create_dataset_version(datasetId=dataset_id)
    ds2 = _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
    )
    assert ds2["status"] == "ACTIVE", f"unexpected terminal status {ds2['status']!r}"

    versions = bac.list_dataset_versions(datasetId=dataset_id)["versions"]
    assert len(versions) == 1, f"expected one published version, got {len(versions)}"

    # Publishing a second version must grow the history, not replace it.
    bac.create_dataset_version(datasetId=dataset_id)
    _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
    )
    versions2 = bac.list_dataset_versions(datasetId=dataset_id)["versions"]
    assert len(versions2) == 2, "version history was orphaned by the second CreateDatasetVersion"

    before_update = bac.get_dataset(datasetId=dataset_id)["updatedAt"]
    update_resp = bac.update_dataset(datasetId=dataset_id, description="sim2real-updated")
    assert update_resp["updatedAt"] >= before_update, (
        f"updatedAt did not advance: before={before_update!r} after={update_resp['updatedAt']!r}"
    )

    bac.delete_dataset(datasetId=dataset_id)
    code, message = _poll_gone(lambda: bac.get_dataset(datasetId=dataset_id), timeout_s=120.0)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = "The specified dataset does not exist. Please verify the datasetId and try again."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # A mutation on the deleted id must also fail, not just the read.
    update_code, update_message = _error_detail(
        lambda: bac.update_dataset(datasetId=dataset_id, description="post-delete-update")
    )
    assert update_code == "ResourceNotFoundException", (
        f"UpdateDataset on a deleted dataset should fail not-found, got {update_code!r}"
    )
    expected_update_message = "The specified dataset does not exist. Please verify the datasetId and try again."
    assert update_message == expected_update_message, f"expected message {expected_update_message!r}, got {update_message!r}"


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_gone(read, timeout_s=120.0, interval_s=3.0):
    """Poll read() until it raises ClientError; return (code, message). Raise on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _safe_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c for c in raw if c.isalnum() or c == "_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _safe_delete(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
