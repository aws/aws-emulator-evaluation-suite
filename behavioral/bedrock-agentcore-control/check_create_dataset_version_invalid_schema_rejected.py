"""create-dataset-version-invalid-schema-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-dataset-version-invalid-schema-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDataset whose second inline example lacks scenario_id is refused whole with ValidationException and the
    exact schema message, creating no dataset; an all-valid batch turns ACTIVE, CreateDatasetVersion answers
    UPDATING, and ListDatasetVersions then shows one version with exampleCount 1."""
    client = ctx.client("bedrock-agentcore-control")

    valid_example = {"scenario_id": "sim2real-scenario-1", "turns": [{"input": "hello"}]}
    invalid_example = {"turns": [{"input": "hello, but no scenario_id"}]}

    bad_name = _pattern_safe_name(ctx, "sim2realdsbadschema")
    code, message = _error_detail(
        lambda: client.create_dataset(
            datasetName=bad_name,
            schemaType="AGENTCORE_EVALUATION_PREDEFINED_V1",
            source={"inlineExamples": {"examples": [valid_example, invalid_example]}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "Example at index 1 failed schema validation: Required field 'scenario_id' is missing from example content"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no dataset was created, not even holding the one valid example.
    assert not _dataset_name_exists(client, bad_name), (
        f"dataset {bad_name} exists despite the wholesale-rejected batch"
    )

    # Positive control: an all-valid batch succeeds and its DRAFT can be published.
    good_name = _pattern_safe_name(ctx, "sim2realdsgoodschema")
    created = client.create_dataset(
        datasetName=good_name,
        schemaType="AGENTCORE_EVALUATION_PREDEFINED_V1",
        source={"inlineExamples": {"examples": [valid_example]}},
        tags={"sim2real": "create-dataset-version-invalid-schema-rejected"},
    )
    dataset_id = created["datasetId"]
    ctx.on_cleanup(lambda: _best_effort_delete_dataset(client, dataset_id))

    ds = _poll_until(
        lambda: client.get_dataset(datasetId=dataset_id),
        lambda d: d["status"] != "CREATING",
        timeout_s=120.0,
        interval_s=4.0,
    )
    assert ds["status"] == "ACTIVE", f"unexpected terminal status {ds['status']!r}"

    version = client.create_dataset_version(datasetId=dataset_id)
    assert version["datasetId"] == dataset_id, (
        f"expected CreateDatasetVersion to echo datasetId {dataset_id}, got {version['datasetId']!r}"
    )
    assert version["status"] == "UPDATING", (
        f"expected UPDATING immediately after CreateDatasetVersion, got {version['status']!r}"
    )

    ds2 = _poll_until(
        lambda: client.get_dataset(datasetId=dataset_id),
        lambda d: d["status"] != "UPDATING",
        timeout_s=120.0,
        interval_s=4.0,
    )
    assert ds2["status"] == "ACTIVE", f"unexpected terminal status after publish {ds2['status']!r}"

    # Terminal read: independent of the mutating CreateDatasetVersion call, at the destination.
    versions = client.list_dataset_versions(datasetId=dataset_id)["versions"]
    assert len(versions) == 1, f"expected exactly one published version, got {len(versions)}"
    assert versions[0]["exampleCount"] == 1, (
        f"expected the published version to carry the single valid example, got {versions[0]['exampleCount']!r}"
    )


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _pattern_safe_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "d" + safe
    return safe[:48]


def _dataset_name_exists(client, name: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_datasets(**kwargs)
        for item in page.get("datasets", []):
            if item.get("datasetName") == name:
                return True
        next_token = page.get("nextToken")
        if not next_token:
            return False


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _best_effort_delete_dataset(client, dataset_id: str) -> None:
    try:
        client.delete_dataset(datasetId=dataset_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
