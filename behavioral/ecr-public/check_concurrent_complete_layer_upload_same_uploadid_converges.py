"""concurrent-complete-layer-upload-same-uploadid-converges."""
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-complete-layer-upload-same-uploadid-converges"
GROUP = 'concurrency'
SERVICES = ['ecr-public']

# NOTE: every byte pushed here is synthetic and meaningless. An ECR Public repository is
# world-visible on gallery.ecr.aws for as long as it exists, so nothing real may be pushed.


def _ecr_public(ctx):
    """ECR Public is us-east-1-only (UnsupportedCommandException elsewhere), so pin the region."""
    return ctx.client("ecr-public", region="us-east-1")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "Name", "Value": name}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Two simultaneous CompleteLayerUpload calls on one uploadId converge: at least one succeeds,
    the blob is AVAILABLE once at its exact size, and each loser gets UploadNotFound or
    LayerAlreadyExists.
    """
    ecr = _ecr_public(ctx)
    name, _ = _create_repository(ctx, ecr)

    blob = b"sim2real-concurrent-complete-" + name.encode() + bytes(range(80))
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()

    upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    account = ctx.client("sts").get_caller_identity()["Account"]
    consumed = (
        f"The upload with id '{upload_id}' in the repository with name '{name}' in registry "
        f"with id '{account}' does not exist"
    )
    already_committed = (
        f"Layer with upload id '{upload_id}' already exists in the repository with name '{name}' "
        f"in registry with id '{account}'"
    )
    uploaded = ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    assert uploaded["lastByteReceived"] == len(blob) - 1, (
        f"the single part reported lastByteReceived {uploaded['lastByteReceived']!r}, expected "
        f"{len(blob) - 1!r}; the race below is only meaningful over a complete upload"
    )

    def _complete(_index):
        try:
            return ("success", ecr.complete_layer_upload(
                repositoryName=name, uploadId=upload_id, layerDigests=[digest]
            ))
        except ClientError as exc:
            return ("failure", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(_complete, range(2)))

    successes = [payload for kind, payload in outcomes if kind == "success"]
    failure_codes = [payload for kind, payload in outcomes if kind == "failure"]
    # A lower bound: a registry may make a byte-identical completion idempotent.
    assert len(successes) >= 1, (
        f"both completions failed and the blob is lost: {outcomes!r}"
    )
    assert {payload["layerDigest"] for payload in successes} == {digest}, (
        f"a completion acknowledged a digest other than the one submitted: {successes!r}"
    )
    assert {payload["uploadId"] for payload in successes} == {upload_id}, (
        f"a completion echoed a different uploadId: {successes!r}"
    )
    # The loser sees UploadNotFound after the winner consumed the id, LayerAlreadyExists if it
    # overlaps the winner's commit.
    loser_refusals = {
        ("UploadNotFoundException", consumed),
        ("LayerAlreadyExistsException", already_committed),
    }
    assert set(failure_codes) <= loser_refusals, (
        f"a loser reported {failure_codes!r}; AWS refuses a racing completion of one upload id "
        f"only as {sorted(loser_refusals)!r}"
    )
    assert len(successes) + len(failure_codes) == 2, f"{outcomes!r}"

    # --- the store holds the blob EXACTLY ONCE, at exactly the uploaded size ---------------------
    availability = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[digest]
    )
    assert not availability.get("failures"), (
        f"BatchCheckLayerAvailability failed for the completed layer: {availability!r}"
    )
    matching = [lay for lay in availability["layers"] if lay["layerDigest"] == digest]
    assert len(matching) == 1, (
        f"the layer is reported {len(matching)} times after two concurrent completions: "
        f"{availability['layers']!r}"
    )
    assert matching[0]["layerAvailability"] == "AVAILABLE", f"{matching[0]!r}"
    assert matching[0]["layerSize"] == len(blob), (
        f"layerSize is {matching[0]['layerSize']!r}; exactly {len(blob)} bytes were uploaded, so a "
        f"different number means the concurrent completions did not converge on one blob"
    )

    # --- the upload id is CONSUMED: replaying the winning call now fails the same way ------------
    try:
        replayed = ecr.complete_layer_upload(
            repositoryName=name, uploadId=upload_id, layerDigests=[digest]
        )
        raise AssertionError(
            f"a consumed uploadId was completed a third time, sequentially: {replayed!r}"
        )
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "UploadNotFoundException", (
            f"replaying the consumed uploadId answered "
            f"{exc.response['Error']['Code']!r}"
        )
        assert exc.response["Error"].get("Message") == consumed, (
            f"UploadNotFoundException message: {exc.response['Error'].get('Message')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
