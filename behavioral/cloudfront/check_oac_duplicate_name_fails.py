"""oac-duplicate-name-fails."""
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
    """ETag-guarded delete of a CloudFront policy-like resource."""
    resp = get_fn(Id=resource_id)
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

def _ids_named(cf, name):
    """Independent read: walk ListOriginAccessControls and collect Ids whose Name matches."""
    ids = []
    marker = None
    for _ in range(1000):  # hard upper bound so a broken NextMarker loop can't hang forever
        kwargs = {"MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        page = cf.list_origin_access_controls(**kwargs)["OriginAccessControlList"]
        ids.extend(item["Id"] for item in page.get("Items", []) if item["Name"] == name)
        marker = page.get("NextMarker")
        if not marker:
            break
    return ids

CHECK = "oac-duplicate-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOriginAccessControl with a Name already in use MUST fail with
    OriginAccessControlAlreadyExists, and MUST NOT create a second OAC under that name. Once
    the name-holding OAC is deleted, the identical create call MUST succeed."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-oac-")
    cfg = {
        "Name": name,
        "Description": "behavioral test",
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    }
    create_resp = cf.create_origin_access_control(OriginAccessControlConfig=cfg)
    oac_id = create_resp["OriginAccessControl"]["Id"]
    holder = {"id": oac_id}
    ctx.on_cleanup(
        lambda: _force_delete(cf.get_origin_access_control, cf.delete_origin_access_control, holder["id"])
    )
    assert create_resp["OriginAccessControl"]["OriginAccessControlConfig"]["Name"] == name, (
        "positive control: the first create with this Name must itself succeed and echo it back"
    )

    code, message = _error(lambda: cf.create_origin_access_control(OriginAccessControlConfig=cfg))
    assert code == "OriginAccessControlAlreadyExists", (
        f"expected OriginAccessControlAlreadyExists, got {code}"
    )
    expected = "An origin access control with the same name already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    matches = _ids_named(cf, name)
    assert matches == [oac_id], (
        f"the rejected duplicate must leave exactly the original OAC {oac_id!r} named {name!r}, "
        f"but ListOriginAccessControls shows {matches}"
    )

    original = cf.get_origin_access_control(Id=oac_id)
    cf.delete_origin_access_control(Id=oac_id, IfMatch=original["ETag"])

    recreated = cf.create_origin_access_control(OriginAccessControlConfig=cfg)
    new_id = recreated["OriginAccessControl"]["Id"]
    holder["id"] = new_id

    got = cf.get_origin_access_control(Id=new_id)
    assert got["OriginAccessControl"]["OriginAccessControlConfig"]["Name"] == name, (
        "restore: once the name-holding OAC is gone, the identical create must succeed and the "
        "new OAC must be independently readable back under that Name"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
