"""upload-layer-part-exceeds-max-size-rejected."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upload-layer-part-exceeds-max-size-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr-public"]

_DOCUMENTED_MAX_PART_BYTES = 10 * 1024 * 1024  # ecr-public's documented "Maximum layer part
# size" quota (10 MiB), per
# https://docs.aws.amazon.com/AmazonECR/latest/public/public-service-quotas.html -- not enforced
# as a per-call InvalidLayerPartException boundary (a part a little over it still uploads); the
# rejection boundary is the front end's raw request-body cap, a bare HTTP 413 with no modeled error.
_OVERSIZED_PART_BYTES = 21 * 1024 * 1024  # comfortably past the documented quota AND past the
# front-end's raw-body cap, so AWS answers HTTP 413.


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UploadLayerPart with a grossly oversized part is refused with a bare HTTP 413, while a
    part within the quota is accepted and its layer completes AVAILABLE at the exact size."""
    ecrpublic = _ecrpublic(ctx)
    repo_name = ctx.unique_name("sim2real-behav-ecrpub-")
    ecrpublic.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ecrpublic.delete_repository(repositoryName=repo_name, force=True))

    upload_id = ecrpublic.initiate_layer_upload(repositoryName=repo_name)["uploadId"]

    # boto3's bundled model would itself reject an oversized blob client-side before it ever
    # reaches the wire (the shape declares a max_length), which would only test botocore's
    # shared model rather than the target service. Disable client-side parameter validation so
    # the oversized request is actually sent and the SERVER's own rejection is what gets
    # exercised.
    unvalidated = _client_without_param_validation(ctx, "ecr-public")
    oversized_blob = b"\x00" * _OVERSIZED_PART_BYTES
    code, message = _error_code(
        lambda: unvalidated.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload_id,
            partFirstByte=0,
            partLastByte=len(oversized_blob) - 1,
            layerPartBlob=oversized_blob,
        )
    )
    assert code == "413", f"expected a 413 rejection for a {_OVERSIZED_PART_BYTES}-byte part, got code={code!r} message={message!r}"

    # A part comfortably within the documented 10 MiB quota is accepted normally -- the
    # rejection above is a genuine size boundary, not a blanket failure of the upload session.
    # Prove it not just via UploadLayerPart's own echoed response but via an independent read
    # at the destination: complete the upload and confirm the layer is actually stored and
    # available, at the exact byte size uploaded.
    within_quota_blob = b"\x02" * (1024 * 1024)
    resp = ecrpublic.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(within_quota_blob) - 1,
        layerPartBlob=within_quota_blob,
    )
    assert resp["lastByteReceived"] == len(within_quota_blob) - 1, (
        f"UploadLayerPart reported lastByteReceived {resp['lastByteReceived']!r}, "
        f"expected {len(within_quota_blob) - 1}"
    )

    expected_digest = "sha256:" + hashlib.sha256(within_quota_blob).hexdigest()
    complete = ecrpublic.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[expected_digest]
    )
    assert complete["layerDigest"] == expected_digest, (
        f"CompleteLayerUpload returned layerDigest {complete['layerDigest']!r}, "
        f"expected {expected_digest!r}"
    )

    avail = ecrpublic.batch_check_layer_availability(
        repositoryName=repo_name, layerDigests=[expected_digest]
    )
    assert avail["failures"] == [], (
        f"BatchCheckLayerAvailability reported failures for {expected_digest!r}: {avail['failures']!r}"
    )
    layer = avail["layers"][0]
    assert layer["layerAvailability"] == "AVAILABLE", (
        f"layer {expected_digest!r} reads layerAvailability {layer['layerAvailability']!r}, expected AVAILABLE"
    )
    assert layer["layerSize"] == len(within_quota_blob), (
        f"layerSize {layer['layerSize']} != uploaded byte count {len(within_quota_blob)} -- "
        f"the rejected oversized part must not have contributed any bytes to the stored layer"
    )


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING a request real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _client_without_param_validation(ctx, service):
    """A client on the same target with botocore's client-side validation off, so the request
    reaches the server."""
    from botocore.config import Config

    return ctx.client(service, region="us-east-1", config=Config(parameter_validation=False))


def _ecrpublic(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so pin that region on the
    target ctx names."""
    from botocore.config import Config

    return ctx.client("ecr-public", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"}))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
