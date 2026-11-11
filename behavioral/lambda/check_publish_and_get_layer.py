"""publish-and-get-layer."""

from __future__ import annotations

import base64
import hashlib
import io
import textwrap
import zipfile

from behavioral_harness import tags


CHECK = "publish-and-get-layer"
GROUP = 'layers'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PublishLayerVersion → GetLayerVersion returns the content metadata."""
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-layer-")
    zip_bytes = _make_zip("LAYER = 1\n", "python/sim2real_layer.py")
    expected_sha256 = base64.b64encode(hashlib.sha256(zip_bytes).digest()).decode()
    resp = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": zip_bytes},
        CompatibleRuntimes=["python3.12"],
    )
    ctx.on_cleanup(lambda n=layer_name, v=resp["Version"]: lam.delete_layer_version(LayerName=n, VersionNumber=v))
    assert resp["Version"] == 1, f"expected Version 1 for a fresh layer, got {resp['Version']!r}"

    get = lam.get_layer_version(LayerName=layer_name, VersionNumber=1)
    assert get["LayerArn"] is not None, "GetLayerVersion returned no LayerArn"
    assert "python3.12" in get["CompatibleRuntimes"], (
        f"expected python3.12 in CompatibleRuntimes, got {get['CompatibleRuntimes']!r}"
    )
    assert get["Content"]["CodeSha256"] == expected_sha256, (
        f"GetLayerVersion reports CodeSha256 {get['Content']['CodeSha256']!r}, expected "
        f"{expected_sha256!r} computed from the uploaded zip bytes"
    )
    assert get["Content"]["CodeSize"] == len(zip_bytes), (
        f"GetLayerVersion reports CodeSize {get['Content']['CodeSize']!r}, expected {len(zip_bytes)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
