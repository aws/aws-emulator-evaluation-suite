"""oac-create-update-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource; one the check already deleted is skipped."""
    try:
        resp = get_fn(Id=resource_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchOriginAccessControl":
            return
        raise
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

CHECK = "oac-create-update-delete-lifecycle"
GROUP = 'origin-access-control'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OriginAccessControl CRUD: create, update SigningBehavior, confirm persisted, delete."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-oac-")
    created = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": name,
        "SigningProtocol": "sigv4",
        "SigningBehavior": "always",
        "OriginAccessControlOriginType": "s3",
    })
    oac_id = created["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_origin_access_control, cf.delete_origin_access_control, oac_id))
    assert created["OriginAccessControl"]["OriginAccessControlConfig"]["SigningBehavior"] == "always"

    got = cf.get_origin_access_control(Id=oac_id)
    cfg = got["OriginAccessControl"]["OriginAccessControlConfig"]
    cfg["SigningBehavior"] = "no-override"
    updated = cf.update_origin_access_control(Id=oac_id, IfMatch=got["ETag"], OriginAccessControlConfig=cfg)
    assert updated["OriginAccessControl"]["OriginAccessControlConfig"]["SigningBehavior"] == "no-override"

    refetched = cf.get_origin_access_control(Id=oac_id)
    refetched_signing_behavior = refetched["OriginAccessControl"]["OriginAccessControlConfig"]["SigningBehavior"]
    assert refetched_signing_behavior == "no-override", (
        f"expected the update to persist SigningBehavior=no-override, got {refetched_signing_behavior}"
    )
    cf.delete_origin_access_control(Id=oac_id, IfMatch=refetched["ETag"])

    code, message = _error(lambda: cf.get_origin_access_control(Id=oac_id))
    assert code == "NoSuchOriginAccessControl", f"expected NoSuchOriginAccessControl, got {code}"
    expected = "The specified origin access control does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
