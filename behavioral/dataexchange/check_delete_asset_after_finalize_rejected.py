"""delete-asset-after-finalize-rejected."""
from __future__ import annotations

import base64
import hashlib
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-asset-after-finalize-rejected"
GROUP = "overly-permissive"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DeleteAsset on an asset that belongs to a finalized revision is rejected and the
    asset stays listed; the same delete succeeds on an equivalent asset in a revision
    that has not been finalized yet (positive control)."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)

    finalized_revision_id = _create_revision(ctx, dx, dataset_id)
    finalized_asset_id = _import_asset_via_signed_url(
        ctx, dx, dataset_id, finalized_revision_id, b"sim2real-finalized-asset", "sim2real-asset.txt"
    )
    dx.update_revision(DataSetId=dataset_id, RevisionId=finalized_revision_id, Finalized=True)

    code, message = _error(
        lambda: dx.delete_asset(
            AssetId=finalized_asset_id, DataSetId=dataset_id, RevisionId=finalized_revision_id
        )
    )
    assert code == "ConflictException", f"expected ConflictException deleting a finalized-revision asset, got {code}"
    assert message == "Cannot take action on a Finalized Revision.", f"expected the exact refusal message, got {message!r}"
    remaining = dx.list_revision_assets(DataSetId=dataset_id, RevisionId=finalized_revision_id)["Assets"]
    assert any(a["Id"] == finalized_asset_id for a in remaining), (
        f"finalized asset {finalized_asset_id} should still be listed after the rejected delete, "
        f"found {[a['Id'] for a in remaining]}"
    )

    # Positive control: deleting an asset in a non-finalized revision succeeds.
    live_revision_id = _create_revision(ctx, dx, dataset_id)
    live_asset_id = _import_asset_via_signed_url(
        ctx, dx, dataset_id, live_revision_id, b"sim2real-live-asset", "sim2real-asset.txt"
    )
    dx.delete_asset(AssetId=live_asset_id, DataSetId=dataset_id, RevisionId=live_revision_id)
    remaining_live = dx.list_revision_assets(DataSetId=dataset_id, RevisionId=live_revision_id)["Assets"]
    assert not any(a["Id"] == live_asset_id for a in remaining_live), (
        f"live asset {live_asset_id} should be gone after delete, found {[a['Id'] for a in remaining_live]}"
    )
    code_after_delete, code_after_delete_message = _error(
        lambda: dx.get_asset(AssetId=live_asset_id, DataSetId=dataset_id, RevisionId=live_revision_id)
    )
    assert code_after_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted asset by id, got {code_after_delete}"
    )
    assert code_after_delete_message == "The requested resource was not found.", f"expected the exact refusal message, got {code_after_delete_message!r}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_revision_unless_finalized(dx, dataset_id: str, revision_id: str) -> None:
    """Teardown: AWS refuses DeleteRevision on a finalized revision; the data set delete removes it."""
    try:
        dx.delete_revision(DataSetId=dataset_id, RevisionId=revision_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConflictException":
            raise


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(AssetType="S3_SNAPSHOT", Description="sim2real check", Name=name)
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


def _create_revision(ctx, dx, dataset_id: str) -> str:
    rev = dx.create_revision(DataSetId=dataset_id, Comment="sim2real revision")
    ctx.on_cleanup(lambda: _delete_revision_unless_finalized(dx, dataset_id, rev["Id"]))
    return rev["Id"]


def _import_asset_via_signed_url(ctx, dx, dataset_id, revision_id, content: bytes, asset_name: str) -> str:
    md5_b64 = base64.b64encode(hashlib.md5(content).digest()).decode()
    job = dx.create_job(
        Type="IMPORT_ASSET_FROM_SIGNED_URL",
        Details={
            "ImportAssetFromSignedUrl": {
                "AssetName": asset_name,
                "DataSetId": dataset_id,
                "Md5Hash": md5_b64,
                "RevisionId": revision_id,
            }
        },
    )
    job_id = job["Id"]
    signed_url, route = ctx.endpoint_route(job["Details"]["ImportAssetFromSignedUrl"]["SignedUrl"])
    req = urllib.request.Request(
        signed_url, data=content, method="PUT", headers={"Content-MD5": md5_b64, **route}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status not in (200, 201):
            raise AssertionError(f"signed URL upload failed: HTTP {resp.status}")
    dx.start_job(JobId=job_id)
    _poll_job_state(ctx, dx, job_id, {"COMPLETED", "ERROR", "TIMED_OUT"}, timeout_s=90)
    final = dx.get_job(JobId=job_id)
    assert final["State"] == "COMPLETED", f"import job ended in {final['State']}: {final.get('Errors')}"
    assets = dx.list_revision_assets(DataSetId=dataset_id, RevisionId=revision_id)["Assets"]
    matches = [a for a in assets if a["Name"] == asset_name]
    assert len(matches) == 1, f"expected exactly one asset named {asset_name}, found {len(matches)}"
    return matches[0]["Id"]


def _poll_job_state(ctx, dx, job_id: str, target_states: set, timeout_s: float = 90.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = dx.get_job(JobId=job_id)["State"]
    while state not in target_states and time.monotonic() < deadline:
        time.sleep(interval_s)
        state = dx.get_job(JobId=job_id)["State"]
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
