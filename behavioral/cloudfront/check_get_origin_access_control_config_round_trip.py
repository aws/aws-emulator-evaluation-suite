"""get-origin-access-control-config-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-origin-access-control-config-round-trip"
GROUP = "representation"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOriginAccessControlConfig returns the signing behavior, signing protocol and
    origin type exactly as configured at creation."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-oac-")

    created = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": name,
            "Description": "sim2real behavioral check origin access control",
            "SigningProtocol": "sigv4",
            "SigningBehavior": "always",
            "OriginAccessControlOriginType": "s3",
        }
    )
    oac_id = created["OriginAccessControl"]["Id"]
    created_etag = created["ETag"]

    def _cleanup():
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
        cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    fetched = cf.get_origin_access_control_config(Id=oac_id)
    config = fetched["OriginAccessControlConfig"]

    assert config["Name"] == name, f"expected Name {name!r}, got {config['Name']!r}"
    assert config["SigningProtocol"] == "sigv4", (
        f"expected SigningProtocol 'sigv4', got {config['SigningProtocol']!r}"
    )
    assert config["SigningBehavior"] == "always", (
        f"expected SigningBehavior 'always', got {config['SigningBehavior']!r}"
    )
    assert config["OriginAccessControlOriginType"] == "s3", (
        f"expected OriginAccessControlOriginType 's3', got {config['OriginAccessControlOriginType']!r}"
    )
    assert fetched["ETag"] == created_etag, (
        f"expected ETag {created_etag!r} unchanged on immediate re-read, got {fetched['ETag']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
