"""data-grant-create-reflects-pending-state."""
from __future__ import annotations

import base64
import datetime
import hashlib
import ssl
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-grant-create-reflects-pending-state"
GROUP = "state-transitions"
SERVICES = ["dataexchange"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateDataGrant starts a grant in PENDING_RECEIVER_ACCEPTANCE with SenderPrincipal
    set to the caller's own account, and GetDataGrant reflects that same state."""
    dx = ctx.client("dataexchange")
    sts = ctx.client("sts")
    caller_account = sts.get_caller_identity()["Account"]

    dataset_id = _create_finalized_dataset(ctx, dx)
    ends_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)

    grant = dx.create_data_grant(
        Name=ctx.unique_name("sim2real-dx-grant-"),
        GrantDistributionScope="NONE",
        ReceiverPrincipal="111122223333",
        SourceDataSetId=dataset_id,
        EndsAt=ends_at,
        Tags={"sim2real:managed": "true"},
    )
    grant_id = grant["Id"]
    ctx.on_cleanup(lambda: dx.delete_data_grant(DataGrantId=grant_id))

    assert grant["AcceptanceState"] == "PENDING_RECEIVER_ACCEPTANCE", (
        f"expected CreateDataGrant to start PENDING_RECEIVER_ACCEPTANCE, got {grant['AcceptanceState']}"
    )
    assert grant["SenderPrincipal"] == caller_account, (
        f"expected SenderPrincipal {caller_account}, got {grant['SenderPrincipal']}"
    )
    assert grant["ReceiverPrincipal"] == "111122223333", (
        f"expected ReceiverPrincipal 111122223333, got {grant['ReceiverPrincipal']}"
    )
    assert "AcceptedAt" not in grant, f"expected no AcceptedAt on a pending grant, got {grant.get('AcceptedAt')}"

    got = dx.get_data_grant(DataGrantId=grant_id)
    assert got["AcceptanceState"] == "PENDING_RECEIVER_ACCEPTANCE", (
        f"expected GetDataGrant to reflect PENDING_RECEIVER_ACCEPTANCE, got {got['AcceptanceState']}"
    )
    assert got["SourceDataSetId"] == dataset_id, (
        f"expected SourceDataSetId {dataset_id}, got {got['SourceDataSetId']}"
    )


def _delete_revision_unless_finalized(dx, dataset_id: str, revision_id: str) -> None:
    """Teardown: AWS refuses DeleteRevision on a finalized revision, which the data set delete
    removes; any other refusal, or a conflict on a revision that is not finalized, raises."""
    try:
        dx.delete_revision(DataSetId=dataset_id, RevisionId=revision_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConflictException":
            raise
        if not dx.get_revision(DataSetId=dataset_id, RevisionId=revision_id).get("Finalized"):
            raise


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(
        AssetType="S3_SNAPSHOT",
        Description="sim2real check",
        Name=name,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


def _create_finalized_dataset(ctx, dx) -> str:
    """CreateDataGrant requires the source data set to have at least one finalized
    revision, so build dataset -> revision -> asset -> finalize before returning."""
    dataset_id = _create_dataset(ctx, dx)
    rev = dx.create_revision(
        DataSetId=dataset_id, Comment="sim2real revision", Tags={"sim2real:managed": "true"}
    )
    revision_id = rev["Id"]
    ctx.on_cleanup(lambda: _delete_revision_unless_finalized(dx, dataset_id, revision_id))

    content = b"sim2real-data-grant-source-asset"
    md5_b64 = base64.b64encode(hashlib.md5(content).digest()).decode()
    job = dx.create_job(
        Type="IMPORT_ASSET_FROM_SIGNED_URL",
        Details={
            "ImportAssetFromSignedUrl": {
                "AssetName": "sim2real-grant-asset.txt",
                "DataSetId": dataset_id,
                "Md5Hash": md5_b64,
                "RevisionId": revision_id,
            }
        },
    )
    job_id = job["Id"]
    signed_url = job["Details"]["ImportAssetFromSignedUrl"]["SignedUrl"]
    # The URL is presigned, so its signature covers the host: send the route headers.
    url, route_headers = ctx.endpoint_route(signed_url)
    req = urllib.request.Request(
        url, data=content, method="PUT", headers={"Content-MD5": md5_b64, **route_headers}
    )
    with urllib.request.urlopen(req, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
        if resp.status not in (200, 201):
            raise AssertionError(f"signed URL upload failed: HTTP {resp.status}")
    dx.start_job(JobId=job_id)
    deadline = time.monotonic() + 90.0
    state = dx.get_job(JobId=job_id)["State"]
    while state not in {"COMPLETED", "ERROR", "TIMED_OUT"} and time.monotonic() < deadline:
        time.sleep(2.0)
        state = dx.get_job(JobId=job_id)["State"]
    assert state == "COMPLETED", f"import job ended in {state}"

    dx.update_revision(DataSetId=dataset_id, RevisionId=revision_id, Finalized=True)
    return dataset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
