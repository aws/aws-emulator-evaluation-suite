"""list-layers-and-versions."""
from __future__ import annotations

import io
import zipfile

from behavioral_harness import tags

CHECK = "list-layers-and-versions"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Newly published layer versions appear in both ListLayers and ListLayerVersions."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-listlayer-")

    v1 = lam.publish_layer_version(
        LayerName=name, Content={"ZipFile": _layer_zip_bytes("v1")}, CompatibleRuntimes=["python3.12"]
    )
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=name, VersionNumber=v1["Version"]))
    v2 = lam.publish_layer_version(
        LayerName=name, Content={"ZipFile": _layer_zip_bytes("v2")}, CompatibleRuntimes=["python3.12"]
    )
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=name, VersionNumber=v2["Version"]))
    assert v2["Version"] == v1["Version"] + 1, (
        f"expected second version to be {v1['Version'] + 1}, got {v2['Version']}"
    )

    versions = _list_layer_versions(lam, name)
    assert v1["Version"] in versions, f"expected {v1['Version']} in ListLayerVersions, got {versions}"
    assert v2["Version"] in versions, f"expected {v2['Version']} in ListLayerVersions, got {versions}"

    layers = _list_layers(lam)
    matching = [layer for layer in layers if layer["LayerName"] == name]
    assert len(matching) == 1, f"expected exactly one matching layer entry, found {len(matching)}"
    latest = matching[0]["LatestMatchingVersion"]["Version"]
    assert latest == v2["Version"], (
        f"expected ListLayers LatestMatchingVersion to be {v2['Version']}, got {latest}"
    )


def _layer_zip_bytes(tag: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("python/marker.txt", f"sim2real behavioral layer content {tag}\n")
    return buf.getvalue()


def _list_layer_versions(lam, layer_name: str) -> list:
    marker = None
    versions: list = []
    while True:
        kwargs = {"LayerName": layer_name, "MaxItems": 50}
        if marker:
            kwargs["Marker"] = marker
        resp = lam.list_layer_versions(**kwargs)
        versions.extend(v["Version"] for v in resp.get("LayerVersions", []))
        marker = resp.get("NextMarker")
        if not marker:
            return versions


def _list_layers(lam) -> list:
    marker = None
    layers: list = []
    while True:
        kwargs = {"CompatibleRuntime": "python3.12", "MaxItems": 50}
        if marker:
            kwargs["Marker"] = marker
        resp = lam.list_layers(**kwargs)
        layers.extend(resp.get("Layers", []))
        marker = resp.get("NextMarker")
        if not marker:
            return layers


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
