"""get-origin-access-control-config-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-origin-access-control-config-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOriginAccessControlConfig with an id that was never created returns
    NoSuchOriginAccessControl, while the identical call against a real origin access
    control (the positive control, same file) succeeds and returns the matching config."""
    cf = ctx.client("cloudfront")

    name = ctx.unique_name("sim2real-oac-")
    create_resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": name,
            "Description": "sim2real oac nonexistent-config negative check",
            "SigningProtocol": "sigv4",
            "SigningBehavior": "always",
            "OriginAccessControlOriginType": "s3",
        }
    )
    oac_id = create_resp["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_origin_access_control(
        Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"]
    ))

    fake_id = ctx.unique_name("nonexistent-oac-")
    code, message = _error(lambda: cf.get_origin_access_control_config(Id=fake_id))
    assert code == "NoSuchOriginAccessControl", f"expected NoSuchOriginAccessControl, got {code!r}"
    assert message == "The specified origin access control does not exist.", (
        f"expected AWS's exact not-found message, got {message!r}"
    )

    # Positive control: the real OAC's config is retrievable and matches what was created.
    got = cf.get_origin_access_control_config(Id=oac_id)["OriginAccessControlConfig"]
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["SigningProtocol"] == "sigv4", f"expected SigningProtocol 'sigv4', got {got['SigningProtocol']!r}"
    assert got["OriginAccessControlOriginType"] == "s3", (
        f"expected OriginAccessControlOriginType 's3', got {got['OriginAccessControlOriginType']!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING an id real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected NoSuchOriginAccessControl, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
