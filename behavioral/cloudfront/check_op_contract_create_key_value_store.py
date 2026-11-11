"""op-contract-createKeyValueStore."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createKeyValueStore"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKeyValueStore returns an ARN/Id and provisioning status; duplicate Name is rejected
    while the name is held, and the same Name becomes creatable again once the holder is deleted."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-")

    resp = cf.create_key_value_store(
        Name=name,
        Comment="sim2real behavioral check",
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
    )
    kvs = resp["KeyValueStore"]
    ctx.on_cleanup(lambda: _delete_kvs(ctx, name))

    assert kvs["Name"] == name, f"expected Name {name!r}, got {kvs['Name']!r}"
    assert kvs["Id"], "expected a non-empty Id in the create response"
    # The KeyValueStore ARN is suffixed with the store's Id (a UUID), not its Name.
    assert kvs["ARN"].endswith(kvs["Id"]), f"expected ARN {kvs['ARN']!r} to end with Id {kvs['Id']!r}"
    assert "key-value-store" in kvs["ARN"], f"expected 'key-value-store' in ARN, got {kvs['ARN']!r}"
    assert kvs["Status"] in ("PROVISIONING", "READY"), f"unexpected Status {kvs['Status']!r}"
    assert resp.get("ETag"), "expected an ETag on create"
    assert resp.get("Location"), "expected a Location header value"

    described = cf.describe_key_value_store(Name=name)["KeyValueStore"]
    assert described["Id"] == kvs["Id"], f"expected Describe to echo Id {kvs['Id']!r}, got {described['Id']!r}"

    # Positive control above already proves a fresh Name succeeds. Now break exactly one thing:
    # a second store under the SAME Name while the first is still live.
    code, message = _error(lambda: cf.create_key_value_store(Name=name, Comment="dup"))
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {code}"
    # AWS answers this refusal with an empty Message element.
    expected = ""
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected duplicate must not have altered the live store or the listing.
    unaffected = cf.describe_key_value_store(Name=name)["KeyValueStore"]
    assert unaffected["Id"] == kvs["Id"], (
        f"expected the rejected duplicate to leave Id {kvs['Id']!r} untouched, got {unaffected['Id']!r}"
    )
    listing = cf.list_key_value_stores()
    matches = [i for i in listing.get("KeyValueStoreList", {}).get("Items", []) or [] if i["Name"] == name]
    assert len(matches) == 1, f"expected exactly one store named {name!r} after the rejected dup, got {len(matches)}"

    # Restore: free the Name by deleting the holder, then prove the identical call now succeeds --
    # showing the rejection was caused by the Name being held, not by the Name itself being invalid.
    live_etag = cf.describe_key_value_store(Name=name)["ETag"]
    cf.delete_key_value_store(Name=name, IfMatch=live_etag)
    gone_code, gone_message = _error(lambda: cf.describe_key_value_store(Name=name))
    assert gone_code == "EntityNotFound", f"expected EntityNotFound after delete, got {gone_code}"
    expected = "The specified KeyValueStore does not exist."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    recreated = cf.create_key_value_store(
        Name=name,
        Comment="dup",
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
    )["KeyValueStore"]
    assert recreated["Name"] == name, f"expected recreated store Name {name!r}, got {recreated['Name']!r}"
    assert recreated["Id"] != kvs["Id"], "expected a fresh Id for the recreated store, got the original's Id"

    # Terminal read: an independent Describe, not the mutating Create's own response.
    final_described = cf.describe_key_value_store(Name=name)["KeyValueStore"]
    assert final_described["Id"] == recreated["Id"], (
        f"expected Describe to echo the recreated Id {recreated['Id']!r}, got {final_described['Id']!r}"
    )


def _delete_kvs(ctx, name: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.describe_key_value_store(Name=name)["ETag"]
        cf.delete_key_value_store(Name=name, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
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
