"""create-data-grant-ends-at-past-rejected."""
from __future__ import annotations

import base64
import datetime
import hashlib
import ssl
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-data-grant-ends-at-past-rejected"
GROUP = "overly-permissive"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateDataGrant rejects an EndsAt timestamp that is already in the past with
    ValidationException and creates nothing, while the identical request with a future
    EndsAt succeeds and GetDataGrant reflects that success independently."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_finalized_dataset(ctx, dx)
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)

    # AWS states the earliest EndsAt it accepts: midnight UTC two calendar days from today.
    earliest = datetime.datetime.now(datetime.timezone.utc).date() + datetime.timedelta(days=2)
    code, message = _error(
        lambda: dx.create_data_grant(
            Name=ctx.unique_name("sim2real-dx-grant-past-"),
            GrantDistributionScope="NONE",
            ReceiverPrincipal="111122223333",
            SourceDataSetId=dataset_id,
            EndsAt=past,
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a past EndsAt, got {code!r}"
    assert message == (
        'The following parameter(s) are not valid: "endDate" must be greater than or equal to '
        f'"{earliest.isoformat()}T00:00:00.000Z".'
    ), f"expected the exact refusal message, got {message!r}"

    created = _grant_ids_from(dx, dataset_id)
    assert not created, f"a rejected past-EndsAt request must not have created a grant: {created}"

    # Positive control: the same request with a future EndsAt succeeds.
    grant = dx.create_data_grant(
        Name=ctx.unique_name("sim2real-dx-grant-future-"),
        GrantDistributionScope="NONE",
        ReceiverPrincipal="111122223333",
        SourceDataSetId=dataset_id,
        EndsAt=future,
    )
    grant_id = grant["Id"]
    ctx.on_cleanup(lambda: dx.delete_data_grant(DataGrantId=grant_id))

    got = dx.get_data_grant(DataGrantId=grant_id)
    assert got["AcceptanceState"] == "PENDING_RECEIVER_ACCEPTANCE", (
        f"expected an independent GetDataGrant read to show PENDING_RECEIVER_ACCEPTANCE, "
        f"got {got['AcceptanceState']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _grant_ids_from(dx, dataset_id: str) -> set:
    """Ids of the account's data grants on ``dataset_id``, over every page."""
    ids = set()
    for page in dx.get_paginator("list_data_grants").paginate():
        ids |= {
            g["Id"]
            for g in page.get("DataGrantSummaries", [])
            if dataset_id in (g.get("SourceDataSetId"), g.get("DataSetId"))
        }
    return ids


def _delete_revision_unless_finalized(dx, dataset_id: str, revision_id: str) -> None:
    """Teardown: AWS refuses DeleteRevision on a finalized revision; the data set delete removes it."""
    try:
        dx.delete_revision(DataSetId=dataset_id, RevisionId=revision_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConflictException":
            raise


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(AssetType="S3_SNAPSHOT", Description="sim2real check", Name=name)
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


def _create_finalized_dataset(ctx, dx) -> str:
    """CreateDataGrant requires the source data set to have at least one finalized
    revision, so build dataset -> revision -> asset -> finalize before returning."""
    dataset_id = _create_dataset(ctx, dx)
    rev = dx.create_revision(DataSetId=dataset_id, Comment="sim2real revision")
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
