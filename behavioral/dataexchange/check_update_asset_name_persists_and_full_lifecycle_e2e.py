"""update-asset-name-persists-and-full-lifecycle-e2e."""
from __future__ import annotations

import base64
import datetime
import hashlib
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-asset-name-persists-and-full-lifecycle-e2e"
GROUP = "e2e"
SERVICES = ["dataexchange"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """UpdateAsset's new name shows in GetAsset and ListRevisionAssets; a finalized revision backs a PENDING grant,
    revokes, refuses DeleteRevision with ConflictException "Cannot take action on a Finalized Revision.",
    and after DeleteDataSet reads and mutations fail with ResourceNotFoundException."""


    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)
    revision_id = _create_revision(ctx, dx, dataset_id)
    old_name = "sim2real-original-name.txt"
    new_name = "sim2real-renamed-name.txt"
    asset_id = _import_asset_via_signed_url(
        ctx, dx, dataset_id, revision_id, b"sim2real-rename-payload", old_name
    )

    dx.update_asset(AssetId=asset_id, DataSetId=dataset_id, Name=new_name, RevisionId=revision_id)

    got = dx.get_asset(AssetId=asset_id, DataSetId=dataset_id, RevisionId=revision_id)
    assert got["Name"] == new_name

    listed = dx.list_revision_assets(DataSetId=dataset_id, RevisionId=revision_id)["Assets"]
    names = {a["Id"]: a["Name"] for a in listed}
    assert names[asset_id] == new_name
    assert old_name not in names.values()

    # ---- End-to-end: carry this same data set through the rest of its producer lifecycle ----
    dx.update_revision(DataSetId=dataset_id, RevisionId=revision_id, Finalized=True)
    finalized = dx.get_revision(DataSetId=dataset_id, RevisionId=revision_id)
    assert finalized["Finalized"] is True

    ends_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
    grant = dx.create_data_grant(
        Name=ctx.unique_name("sim2real-dx-grant-e2e-"),
        GrantDistributionScope="NONE",
        ReceiverPrincipal="111122223333",
        SourceDataSetId=dataset_id,
        EndsAt=ends_at,
        Tags={"sim2real": CHECK},
    )
    grant_id = grant["Id"]
    assert grant["AcceptanceState"] == "PENDING_RECEIVER_ACCEPTANCE"
    got_grant = dx.get_data_grant(DataGrantId=grant_id)
    assert got_grant["AcceptanceState"] == "PENDING_RECEIVER_ACCEPTANCE"

    # Revoke is permitted here: the revision currently backs a live data grant.
    dx.revoke_revision(
        DataSetId=dataset_id, RevisionId=revision_id, RevocationComment="sim2real e2e teardown"
    )
    revoked = dx.get_revision(DataSetId=dataset_id, RevisionId=revision_id)
    assert revoked["Revoked"] is True

    # The docstring's claim that a revoked, finalized revision is now permanently
    # immutable is only real if DeleteRevision actually rejects it on its own.
    code_delete_revision, code_delete_revision_message = _error(
        lambda: dx.delete_revision(DataSetId=dataset_id, RevisionId=revision_id)
    )
    assert code_delete_revision == "ConflictException", code_delete_revision
    assert code_delete_revision_message == "Cannot take action on a Finalized Revision.", f"expected the exact refusal message, got {code_delete_revision_message!r}"
    still_present = dx.get_revision(DataSetId=dataset_id, RevisionId=revision_id)
    assert still_present["Revoked"] is True

    dx.delete_data_grant(DataGrantId=grant_id)
    listed_grants = {g["Id"] for g in dx.list_data_grants().get("DataGrantSummaries", [])}
    assert grant_id not in listed_grants

    # DeleteDataSet cascades over the now-permanently-immutable revoked revision,
    # since DeleteRevision alone (just proven above) rejects it.
    dx.delete_data_set(DataSetId=dataset_id)
    code_after_delete, code_after_delete_message = _error(lambda: dx.get_data_set(DataSetId=dataset_id))
    assert code_after_delete == "ResourceNotFoundException"
    assert code_after_delete_message == "The requested resource was not found.", f"expected the exact refusal message, got {code_after_delete_message!r}"

    # Deletes prove gone AND unusable: a mutation against the dead data set also fails.
    code_mutate_after_delete, code_mutate_after_delete_message = _error(
        lambda: dx.update_data_set(DataSetId=dataset_id, Name="sim2real-post-delete-mutation")
    )
    assert code_mutate_after_delete == "ResourceNotFoundException"
    assert code_mutate_after_delete_message == "The requested resource was not found.", f"expected the exact refusal message, got {code_mutate_after_delete_message!r}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(
        AssetType="S3_SNAPSHOT",
        Description="sim2real check",
        Name=name,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: dx.delete_data_set(DataSetId=ds["Id"])))
    return ds["Id"]


def _create_revision(ctx, dx, dataset_id: str) -> str:
    rev = dx.create_revision(
        DataSetId=dataset_id, Comment="sim2real revision", Tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: dx.delete_revision(DataSetId=dataset_id, RevisionId=rev["Id"])
        )
    )
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

