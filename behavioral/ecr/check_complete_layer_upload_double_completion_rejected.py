"""complete-layer-upload-double-completion-rejected."""
from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-layer-upload-double-completion-rejected"
GROUP = "concurrency"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two racing CompleteLayerUpload calls on one uploadId exactly one commits the layer and
    the other fails; a later completion on the consumed uploadId gets UploadNotFoundException."""
    ecr = ctx.client("ecr")
    repo = ecr.create_repository(
        repositoryName=_ecr_name(ctx, "sim2real-cluc"),
        tags=[{"Key": "sim2real", "Value": "complete-layer-upload-double-completion-rejected"}],
    )["repository"]["repositoryName"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo, force=True))

    content = b"sim2real-ecr-complete-layer-upload-race-content"
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(content) - 1,
        layerPartBlob=content,
    )

    def _complete():
        try:
            resp = ecr.complete_layer_upload(repositoryName=repo, uploadId=upload_id, layerDigests=[digest])
            return ("ok", resp["layerDigest"])
        except ClientError as err:
            return ("error", (err.response["Error"]["Code"], err.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [f.result() for f in [pool.submit(_complete), pool.submit(_complete)]]

    kinds = [kind for kind, _ in outcomes]
    assert kinds.count("ok") == 1, f"expected exactly one winner, got {outcomes}"
    assert kinds.count("error") == 1, f"expected exactly one loser, got {outcomes}"
    winner_digest = next(value for kind, value in outcomes if kind == "ok")
    assert winner_digest == digest, f"winner committed {winner_digest!r}, expected {digest!r}"

    # The loser's code depends on where it lost the race; each code has one exact message.
    where = (
        f"in the repository with name '{repo}' in registry with id '{ctx.account}'"
    )
    loser_messages = {
        "UploadNotFoundException": f"The upload with id '{upload_id}' {where} does not exist",
        "LayerAlreadyExistsException": f"Layer with upload id '{upload_id}' already exists {where}",
    }
    loser_code, loser_message = next(value for kind, value in outcomes if kind == "error")
    assert loser_code in loser_messages, (
        f"expected UploadNotFoundException or LayerAlreadyExistsException, got {loser_code}"
    )
    assert loser_message == loser_messages[loser_code], (
        f"expected message {loser_messages[loser_code]!r}, got {loser_message!r}"
    )

    sequential_err, sequential_message = _error(
        lambda: ecr.complete_layer_upload(repositoryName=repo, uploadId=upload_id, layerDigests=[digest])
    )
    assert sequential_err == "UploadNotFoundException", (
        f"expected re-completion to be rejected, got {sequential_err}"
    )
    assert sequential_message == loser_messages["UploadNotFoundException"], (
        f"expected message {loser_messages['UploadNotFoundException']!r}, got {sequential_message!r}"
    )

    availability = ecr.batch_check_layer_availability(repositoryName=repo, layerDigests=[digest])
    assert availability["layers"][0]["layerAvailability"] == "AVAILABLE", (
        f"expected {digest} AVAILABLE after the race settled, got {availability['layers']}"
    )
    assert not availability["failures"], f"expected no failures, got {availability['failures']}"


def _ecr_name(ctx, base: str, max_len: int = 200) -> str:
    raw = ctx.unique_name(base).lower()
    raw = re.sub(r"[^a-z0-9\-]", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    return raw[:max_len]


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
