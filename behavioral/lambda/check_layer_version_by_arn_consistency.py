"""layer-version-by-arn-consistency."""
from __future__ import annotations

import io
import zipfile

from behavioral_harness import tags

CHECK = "layer-version-by-arn-consistency"
GROUP = "layers"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLayerVersionByArn returns identical data to GetLayerVersion for the same layer version."""
    layer = _publish_layer(ctx)
    lam = ctx.client("lambda")

    by_name = lam.get_layer_version(LayerName=layer["name"], VersionNumber=layer["version"])
    by_arn = lam.get_layer_version_by_arn(Arn=layer["arn"])

    for field in ("LayerArn", "LayerVersionArn", "Version", "CompatibleRuntimes", "CreatedDate"):
        assert by_name[field] == by_arn[field], (
            f"{field} mismatch between GetLayerVersion ({by_name[field]!r}) and "
            f"GetLayerVersionByArn ({by_arn[field]!r})"
        )
    assert by_name["Content"]["CodeSha256"] == by_arn["Content"]["CodeSha256"], (
        f"CodeSha256 mismatch between GetLayerVersion ({by_name['Content']['CodeSha256']!r}) and "
        f"GetLayerVersionByArn ({by_arn['Content']['CodeSha256']!r})"
    )
    assert by_name["Content"]["CodeSize"] == by_arn["Content"]["CodeSize"], (
        f"CodeSize mismatch between GetLayerVersion ({by_name['Content']['CodeSize']!r}) and "
        f"GetLayerVersionByArn ({by_arn['Content']['CodeSize']!r})"
    )
    assert by_name["LayerVersionArn"] == layer["arn"], (
        f"expected LayerVersionArn {layer['arn']!r}, got {by_name['LayerVersionArn']!r}"
    )


def _layer_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("python/marker.txt", "sim2real behavioral layer content\n")
    return buf.getvalue()


def _publish_layer(ctx) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-layerarn-")
    resp = lam.publish_layer_version(
        LayerName=name,
        Content={"ZipFile": _layer_zip_bytes()},
        CompatibleRuntimes=["python3.12"],
    )
    version = resp["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=name, VersionNumber=version))
    return {"name": name, "version": version, "arn": resp["LayerVersionArn"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
