"""update-revoked-revision-rejected."""
from __future__ import annotations

import base64
import datetime
import hashlib
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-revoked-revision-rejected"
GROUP = "overly-permissive"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """UpdateRevision on a revoked revision fails with ConflictException "Cannot take action on a Finalized
    Revision." and leaves its Comment unchanged, while the same Comment edit on an unrevoked revision persists."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)

    revoked_revision_id = _create_revision(ctx, dx, dataset_id, comment="original comment")
    _import_asset_via_signed_url(
        ctx, dx, dataset_id, revoked_revision_id, b"sim2real-revoked-asset", "sim2real-asset.txt"
    )
    dx.update_revision(DataSetId=dataset_id, RevisionId=revoked_revision_id, Finalized=True)

    ends_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
    grant = dx.create_data_grant(
        Name=ctx.unique_name("sim2real-dx-grant-"),
        GrantDistributionScope="NONE",
        ReceiverPrincipal="111122223333",
        SourceDataSetId=dataset_id,
        EndsAt=ends_at,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: dx.delete_data_grant(DataGrantId=grant["Id"]))

    dx.revoke_revision(
        DataSetId=dataset_id, RevisionId=revoked_revision_id, RevocationComment="revoked for testing"
    )

    code, message = _error(
        lambda: dx.update_revision(
            DataSetId=dataset_id, RevisionId=revoked_revision_id, Comment="attempted new comment"
        )
    )
    assert code == "ConflictException", f"expected ConflictException updating a revoked revision, got {code!r}"
    assert message == "Cannot take action on a Finalized Revision.", f"expected the exact refusal message, got {message!r}"
    unchanged = dx.get_revision(DataSetId=dataset_id, RevisionId=revoked_revision_id)
    assert unchanged["Comment"] == "original comment", (
        f"expected Comment to remain 'original comment' after the rejected update, got {unchanged['Comment']!r}"
    )

    # Positive control: the same kind of edit succeeds on a non-revoked revision.
    live_revision_id = _create_revision(ctx, dx, dataset_id, comment="live original comment")
    dx.update_revision(DataSetId=dataset_id, RevisionId=live_revision_id, Comment="live updated comment")
    updated = dx.get_revision(DataSetId=dataset_id, RevisionId=live_revision_id)
    assert updated["Comment"] == "live updated comment", (
        f"expected Comment to be updated on a non-revoked revision, got {updated['Comment']!r}"
    )


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
    ds = dx.create_data_set(
        AssetType="S3_SNAPSHOT", Description="sim2real check", Name=name, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


def _create_revision(ctx, dx, dataset_id: str, comment: str = "sim2real revision") -> str:
    rev = dx.create_revision(DataSetId=dataset_id, Comment=comment, Tags={"sim2real-check": CHECK})
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
    return job_id


def _poll_job_state(ctx, dx, job_id: str, target_states: set, timeout_s: float = 90.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = dx.get_job(JobId=job_id)["State"]
    while state not in target_states:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"job {job_id} did not reach {target_states} within {timeout_s}s (last state: {state})")
        time.sleep(interval_s)
        state = dx.get_job(JobId=job_id)["State"]
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
