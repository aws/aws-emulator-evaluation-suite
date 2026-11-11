"""layer-version-numbering."""

from __future__ import annotations

import io
import textwrap
import zipfile

from behavioral_harness import tags


CHECK = "layer-version-numbering"
GROUP = 'layers'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Layer versions are numbered strictly increasing per layer and listed in that order."""
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-layer-")
    published = []
    for i in range(3):
        content = _make_zip(f"marker = {i}\n", "python/marker.py")
        layer = lam.publish_layer_version(
            LayerName=layer_name, Content={"ZipFile": content}, CompatibleRuntimes=["python3.12"]
        )
        version = layer["Version"]
        ctx.on_cleanup(lambda v=version: lam.delete_layer_version(LayerName=layer_name, VersionNumber=v))
        published.append(version)

    assert published == sorted(published), f"expected strictly increasing version numbers, got {published}"
    assert published[1] == published[0] + 1 and published[2] == published[1] + 1, (
        f"expected consecutive integers, got {published}"
    )

    first = lam.list_layer_versions(LayerName=layer_name)["LayerVersions"]
    second = lam.list_layer_versions(LayerName=layer_name)["LayerVersions"]
    first_versions = [v["Version"] for v in first]
    second_versions = [v["Version"] for v in second]

    assert set(first_versions) == set(published), f"expected all published versions listed, got {first_versions}"
    assert first_versions == second_versions, (
        f"expected ListLayerVersions order to be stable across calls, got {first_versions} then {second_versions}"
    )
    is_ascending = first_versions == sorted(first_versions)
    is_descending = first_versions == sorted(first_versions, reverse=True)
    assert is_ascending or is_descending, (
        f"expected ListLayerVersions to return a monotonic (ascending or descending) version order, "
        f"got {first_versions}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
