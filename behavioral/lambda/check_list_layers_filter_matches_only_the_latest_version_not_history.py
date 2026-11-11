"""list-layers-filter-matches-only-the-latest-version-not-history."""

from __future__ import annotations

import io
import zipfile

from behavioral_harness import tags

CHECK = "list-layers-filter-matches-only-the-latest-version-not-history"
GROUP = "layers"
SERVICES = ["lambda"]


def _zip(marker: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("helper.py", marker)
    return buf.getvalue()


def _find_layer(lam, layer_name: str, compatible_runtime: str):
    """Paginate ListLayers for the named layer; other layers in the account are ignored."""
    paginator = lam.get_paginator("list_layers")
    for page in paginator.paginate(CompatibleRuntime=compatible_runtime):
        for layer in page.get("Layers", []):
            if layer["LayerName"] == layer_name:
                return layer
    return None


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListLayers' CompatibleRuntime filter matches a layer only when its newest version carries
    the runtime; it never backtracks to an older match, which ListLayerVersions still reports.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_ListLayers.html
    """
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-layer-")

    v1 = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": _zip("v1")}, CompatibleRuntimes=["python3.12"]
    )
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=v1["Version"]))
    v2 = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": _zip("v2")}, CompatibleRuntimes=["python3.13"]
    )
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=v2["Version"]))
    assert v2["Version"] == v1["Version"] + 1, (
        f"expected v2 ({v2['Version']}) to be the version right after v1 ({v1['Version']})"
    )

    # Positive control: while v2 (python3.13) is still the newest version, the filter finds it
    # and reports exactly that version as LatestMatchingVersion.
    found_before = _find_layer(lam, layer_name, "python3.13")
    assert found_before is not None, (
        f"expected {layer_name!r} in ListLayers(CompatibleRuntime=python3.13) while v2 "
        f"({v2['Version']}) — python3.13 — is the newest version, got no match"
    )
    assert found_before["LatestMatchingVersion"]["Version"] == v2["Version"], (
        f"expected LatestMatchingVersion.Version == {v2['Version']}, "
        f"got {found_before['LatestMatchingVersion']['Version']!r}"
    )

    # Break: publish v3 with a DIFFERENT runtime, so python3.13 is no longer the newest version.
    v3 = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": _zip("v3")}, CompatibleRuntimes=["nodejs22.x"]
    )
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=v3["Version"]))
    assert v3["Version"] == v2["Version"] + 1, (
        f"expected v3 ({v3['Version']}) to be the version right after v2 ({v2['Version']})"
    )

    # The subject under test: the layer must now be ABSENT from the python3.13-filtered
    # listing, even though v2 (python3.13) still exists and is still returned by
    # ListLayerVersions. ListLayers never backtracks past the newest version.
    found_after = _find_layer(lam, layer_name, "python3.13")
    assert found_after is None, (
        f"expected {layer_name!r} to drop out of ListLayers(CompatibleRuntime=python3.13) once "
        f"a newer, non-matching version ({v3['Version']}) exists, got {found_after!r}"
    )

    # Independent confirmation the version itself is untouched: ListLayerVersions (which scans
    # the whole history, not just the newest) still reports v2 under the same filter.
    still_listed = {
        v["Version"]
        for v in lam.list_layer_versions(LayerName=layer_name, CompatibleRuntime="python3.13")[
            "LayerVersions"
        ]
    }
    assert still_listed == {v2["Version"]}, (
        f"expected ListLayerVersions(CompatibleRuntime=python3.13) to still report {{{v2['Version']}}}, "
        f"got {still_listed!r}"
    )

    # Positive control: the filter that DOES match the newest version (nodejs22.x / v3) still
    # finds the layer, with LatestMatchingVersion correctly pointing at v3.
    found_latest = _find_layer(lam, layer_name, "nodejs22.x")
    assert found_latest is not None, (
        f"expected {layer_name!r} in ListLayers(CompatibleRuntime=nodejs22.x) since v3 "
        f"({v3['Version']}) — the newest version — carries that runtime, got no match"
    )
    assert found_latest["LatestMatchingVersion"]["Version"] == v3["Version"], (
        f"expected LatestMatchingVersion.Version == {v3['Version']}, "
        f"got {found_latest['LatestMatchingVersion']['Version']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
