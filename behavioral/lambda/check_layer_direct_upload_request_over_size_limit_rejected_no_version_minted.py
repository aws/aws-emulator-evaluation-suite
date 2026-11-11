"""layer-direct-upload-request-over-size-limit-rejected-no-version-minted."""
from __future__ import annotations

import io
import os
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "layer-direct-upload-request-over-size-limit-rejected-no-version-minted"
GROUP = "packaging"
SERVICES = ["lambda"]

# The RequestEntityTooLargeException threshold for a direct-upload request body, as the error
# message asserted below states it.
REQUEST_SIZE_LIMIT_BYTES = 70167211


def _zip(entries: dict, *, padding_bytes: int = 0) -> bytes:
    """A real, valid zip whose ON-DISK size is cheap to control: ZIP_STORED (no compression)
    plus a padding member sized directly, so a large member costs no compression work."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
        if padding_bytes:
            zf.writestr("padding.bin", os.urandom(padding_bytes))
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes
    mean the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_layer_versions(lam, layer_name: str) -> None:
    """Delete every version of ``layer_name``; a version already gone is fine."""
    for v in lam.list_layer_versions(LayerName=layer_name).get("LayerVersions", []):
        _teardown(lambda n=v["Version"]: lam.delete_layer_version(LayerName=layer_name, VersionNumber=n),
                  "ResourceNotFoundException")()


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An oversized direct-upload PublishLayerVersion request is rejected with
    RequestEntityTooLargeException and mints no new layer version; a small control layer
    publishes successfully.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-function-zip.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html
    """
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-l8lsz-")

    # Positive control: a small layer publishes fine.
    small = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": _zip({"python/marker.py": "MARKER = 1\n"})}
    )
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=small["Version"]),
        "ResourceNotFoundException",
    ))
    assert small["Version"] == 1, f"expected the control publish to mint version 1, got {small!r}"

    # Base64 encoding inflates the raw zip by 4/3 before it reaches the request-size cap; pad
    # comfortably past the point where that inflation alone would exceed the cap.
    min_raw_bytes = (REQUEST_SIZE_LIMIT_BYTES * 3 + 3) // 4
    oversized = _zip(
        {"python/marker.py": "MARKER = 1\n"}, padding_bytes=min_raw_bytes + 256 * 1024
    )

    # A target that wrongly accepts the oversized publish mints a version; delete whatever exists.
    ctx.on_cleanup(lambda: _delete_layer_versions(lam, layer_name))
    code, message = _error(
        lambda: lam.publish_layer_version(LayerName=layer_name, Content={"ZipFile": oversized})
    )
    assert code == "RequestEntityTooLargeException", (
        f"expected a {len(oversized)}-byte direct-upload PublishLayerVersion request to be "
        f"rejected with RequestEntityTooLargeException, got {code}: {message!r}"
    )
    assert message == (
        f"Request must be smaller than {REQUEST_SIZE_LIMIT_BYTES} bytes for the "
        f"PublishLayerVersion operation"
    ), f"unexpected RequestEntityTooLargeException message: {message!r}"

    versions = lam.list_layer_versions(LayerName=layer_name)["LayerVersions"]
    numbers = sorted(v["Version"] for v in versions)
    assert numbers == [1], (
        f"a rejected PublishLayerVersion must mint nothing: expected only version 1 (the "
        f"control) to exist, got {numbers!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
