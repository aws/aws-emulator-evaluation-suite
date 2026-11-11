"""get-map-sprites-rejects-unsupported-file-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-map-sprites-rejects-unsupported-file-name"
GROUP = 'maps'
SERVICES = ['location']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """GetMapSprites serves every documented sprite sheet variant for a style but
    rejects a file name outside the sprites(@2x)?.(png|json) family.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_GetMapSprites.html
    """
    loc = ctx.client("location")
    map_name = ctx.unique_name("sim2real-behav-location-map-")
    loc.create_map(MapName=map_name, Configuration={"Style": "VectorEsriStreets"})
    ctx.on_cleanup(_teardown(lambda: loc.delete_map(MapName=map_name), "ResourceNotFoundException"))

    for file_name, content_type in (
        ("sprites.png", "image/png"),
        ("sprites.json", "application/json"),
        ("sprites@2x.png", "image/png"),
    ):
        sprite = loc.get_map_sprites(MapName=map_name, FileName=file_name)
        assert sprite["ContentType"] == content_type, (
            f"{file_name}: expected content type {content_type!r}, got {sprite['ContentType']!r}"
        )
        assert sprite["Blob"].read(), f"{file_name}: expected a non-empty sprite body"

    try:
        loc.get_map_sprites(MapName=map_name, FileName="unknown.png")
        raise AssertionError("expected an unsupported sprite file name to be rejected")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
        expected = "'FileName' must match regex ^sprites(@2x)?\\.(png|json)$"
        assert err["Message"] == expected, f"unexpected message {err['Message']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
