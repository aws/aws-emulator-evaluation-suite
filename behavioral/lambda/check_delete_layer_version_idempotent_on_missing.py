"""delete-layer-version-idempotent-on-missing."""
from __future__ import annotations

import io
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-layer-version-idempotent-on-missing"
GROUP = "layers"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLayerVersion on an already-deleted (LayerName, VersionNumber) is idempotent
    and does not raise, and the version stays gone throughout."""
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-lambda-layer-idem-")
    content = _make_zip("# idempotent delete test\n")

    v1 = lam.publish_layer_version(LayerName=layer_name, Content={"ZipFile": content})
    version = v1["Version"]
    ctx.on_cleanup(lambda: _cleanup_layer_version(lam, layer_name, version))

    # positive control: the version is really there before we touch it
    got = lam.get_layer_version(LayerName=layer_name, VersionNumber=version)
    assert got["Version"] == version, got

    lam.delete_layer_version(LayerName=layer_name, VersionNumber=version)

    # independent read at the destination proves the first delete had real effect
    code, code_msg = _client_error(lambda: lam.get_layer_version(LayerName=layer_name, VersionNumber=version))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after first delete, got {code!r}"
    )
    expected_code_msg = "The resource you requested does not exist."
    assert code_msg == expected_code_msg, (
        f"expected message {expected_code_msg!r}, got {code_msg!r}"
    )

    # deleting again must not raise per Lambda's documented idempotent-delete semantics
    lam.delete_layer_version(LayerName=layer_name, VersionNumber=version)

    # still gone, unaffected by the redundant delete
    code_after, code_after_msg = _client_error(lambda: lam.get_layer_version(LayerName=layer_name, VersionNumber=version))
    assert code_after == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after second (idempotent) delete, got {code_after!r}"
    )
    expected_code_after_msg = "The resource you requested does not exist."
    assert code_after_msg == expected_code_after_msg, (
        f"expected message {expected_code_after_msg!r}, got {code_after_msg!r}"
    )


def _make_zip(src: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
    return buf.getvalue()


def _client_error(fn):
    """(code, message) of a call that must be refused; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _cleanup_layer_version(lam, layer_name: str, version: int) -> None:
    """Safety net for a mid-check failure; a no-op once the check has deleted it."""
    try:
        lam.delete_layer_version(LayerName=layer_name, VersionNumber=version)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
