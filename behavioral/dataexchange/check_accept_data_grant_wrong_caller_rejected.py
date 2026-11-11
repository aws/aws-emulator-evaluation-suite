"""accept-data-grant-wrong-caller-rejected."""
from __future__ import annotations

import base64
import datetime
import hashlib
import ssl
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "accept-data-grant-wrong-caller-rejected"
GROUP = "overly-permissive"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A grant naming the caller's own account is accepted (ACCEPTED with AcceptedAt), while AcceptDataGrant on
    a grant for another receiver fails with ResourceNotFoundException "The requested resource was not
    found." and the grant stays PENDING_RECEIVER_ACCEPTANCE without AcceptedAt."""
    dx = ctx.client("dataexchange")
    sts = ctx.client("sts")
    caller_account = sts.get_caller_identity()["Account"]
    dataset_id = _create_finalized_dataset(ctx, dx)
    ends_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)

    # Positive control: the caller *is* the receiver principal, so AcceptDataGrant succeeds.
    self_grant = dx.create_data_grant(
        Name=ctx.unique_name("sim2real-dx-grant-self-"),
        GrantDistributionScope="NONE",
        ReceiverPrincipal=caller_account,
        SourceDataSetId=dataset_id,
        EndsAt=ends_at,
        Tags={"sim2real-owner": "behavioral-check", "sim2real-env": "test"},
    )
    self_grant_id = self_grant["Id"]
    ctx.on_cleanup(lambda: dx.delete_data_grant(DataGrantId=self_grant_id))
    accepted = dx.accept_data_grant(DataGrantArn=self_grant["Arn"])
    assert accepted["AcceptanceState"] == "ACCEPTED", (
        f"expected the matching-identity accept to reach ACCEPTED, got {accepted['AcceptanceState']!r}"
    )
    assert "AcceptedAt" in accepted, "a successful accept must report AcceptedAt"
    got_self = dx.get_data_grant(DataGrantId=self_grant_id)
    assert got_self["AcceptanceState"] == "ACCEPTED", (
        f"independent read expected ACCEPTED, got {got_self['AcceptanceState']!r}"
    )

    # Break exactly one thing: the receiver principal is now a different account.
    grant = dx.create_data_grant(
        Name=ctx.unique_name("sim2real-dx-grant-"),
        GrantDistributionScope="NONE",
        ReceiverPrincipal="111122223333",
        SourceDataSetId=dataset_id,
        EndsAt=ends_at,
        Tags={"sim2real-owner": "behavioral-check", "sim2real-env": "test"},
    )
    grant_id = grant["Id"]
    grant_arn = grant["Arn"]
    ctx.on_cleanup(lambda: dx.delete_data_grant(DataGrantId=grant_id))

    # The sender (a non-receiver caller) can still read the grant.
    readback = dx.get_data_grant(DataGrantId=grant_id)
    assert readback["AcceptanceState"] == "PENDING_RECEIVER_ACCEPTANCE", (
        f"expected PENDING_RECEIVER_ACCEPTANCE, got {readback['AcceptanceState']!r}"
    )

    code, message = _error(lambda: dx.accept_data_grant(DataGrantArn=grant_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a wrong-caller accept, got {code!r}"
    )
    assert message == "The requested resource was not found.", f"expected the exact refusal message, got {message!r}"

    still_pending = dx.get_data_grant(DataGrantId=grant_id)
    assert still_pending["AcceptanceState"] == "PENDING_RECEIVER_ACCEPTANCE", (
        f"expected the grant to stay PENDING_RECEIVER_ACCEPTANCE, got {still_pending['AcceptanceState']!r}"
    )
    assert "AcceptedAt" not in still_pending, "a rejected accept must not stamp AcceptedAt"


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
        Tags={"sim2real-owner": "behavioral-check", "sim2real-env": "test"},
    )
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

