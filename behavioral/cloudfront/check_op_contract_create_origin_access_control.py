"""op-contract-createOriginAccessControl."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createOriginAccessControl"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOriginAccessControl echoes the submitted config; duplicate Name is rejected."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-oac-")

    config = {
        "Name": name,
        "Description": "sim2real behavioral check",
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    }
    resp = cf.create_origin_access_control(OriginAccessControlConfig=config)
    oac = resp["OriginAccessControl"]
    oac_id = oac["Id"]
    ctx.on_cleanup(lambda: _delete_oac(ctx, oac_id))

    assert oac_id, "expected CreateOriginAccessControl to return a non-empty Id"
    assert oac["OriginAccessControlConfig"] == config, (
        f"expected the echoed config to equal the submitted config, got {oac['OriginAccessControlConfig']!r}"
    )
    assert resp.get("ETag"), "expected an ETag on create"
    assert resp.get("Location"), "expected a Location header value"

    got = cf.get_origin_access_control(Id=oac_id)["OriginAccessControl"]
    assert got["OriginAccessControlConfig"]["Name"] == name, (
        f"expected GetOriginAccessControl to report Name {name!r}, got {got['OriginAccessControlConfig']['Name']!r}"
    )

    # Distinct error boundary: a second OAC with the same Name is rejected.
    code, message = _error(
        lambda: cf.create_origin_access_control(
            OriginAccessControlConfig={**config, "Description": "dup"}
        )
    )
    assert code == "OriginAccessControlAlreadyExists", f"expected OriginAccessControlAlreadyExists, got {code}"
    expected = "An origin access control with the same name already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _delete_oac(ctx, oac_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
        cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
            raise


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
