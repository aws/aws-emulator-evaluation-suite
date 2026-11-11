"""update-anycast-ip-list-invalid-argument-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-anycast-ip-list-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAnycastIpList with a malformed IpAddressType is rejected with InvalidArgument without
    advancing the list's version, while a valid value succeeds; at the zero-quota default the create
    itself is refused with its specific code while a sibling CloudFront create succeeds.
    """
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real_anycast_").replace("-", "_")[:64]

    try:
        created = cf.create_anycast_ip_list(Name=name, IpCount=3)
    except Exception as exc:  # noqa: BLE001 -- the entitlement gate itself is the contract below
        error = getattr(exc, "response", {}).get("Error", {})
        code = error.get("Code")
        if code not in ("UnsupportedOperation", "EntityLimitExceeded"):
            raise
        if code == "EntityLimitExceeded":
            expected_message = (
                "To request a limit increase for your Anycast static IP list, contact AWS Support: "
                "https://us-east-1.console.aws.amazon.com/servicequotas/home/services/cloudfront/quotas/L-6A19EDFD"
            )
            assert error.get("Message") == expected_message, (
                f"expected message {expected_message!r}, got {error.get('Message')!r}"
            )
        _assert_entitlement_gate_withheld(ctx, cf, name, code)
        return
    anycast_id = created["AnycastIpList"]["Id"]
    etag = created["ETag"]
    original_ip_type = created["AnycastIpList"]["IpAddressType"]

    def _cleanup_anycast_list():
        try:
            current_etag = cf.get_anycast_ip_list(Id=anycast_id)["ETag"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
        cf.delete_anycast_ip_list(Id=anycast_id, IfMatch=current_etag)

    ctx.on_cleanup(_cleanup_anycast_list)

    code, message = _error(
        lambda: cf.update_anycast_ip_list(Id=anycast_id, IfMatch=etag, IpAddressType="ipv7-bogus")
    )
    # message varies: an account at the zero Anycast list quota refuses CreateAnycastIpList above,
    # so this update is not reached there.
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r} ({message!r})"

    # Effect absent: the list's configuration and version are untouched.
    after = cf.get_anycast_ip_list(Id=anycast_id)
    assert after["AnycastIpList"]["IpAddressType"] == original_ip_type, (
        f"IpAddressType changed to {after['AnycastIpList']['IpAddressType']!r} despite the "
        f"rejected update (expected it to stay {original_ip_type!r})"
    )
    assert after["ETag"] == etag, "the anycast list's version advanced despite the rejected update"

    # Positive control: re-asserting a valid IpAddressType value still succeeds.
    updated = cf.update_anycast_ip_list(Id=anycast_id, IfMatch=etag, IpAddressType=original_ip_type)
    assert updated["AnycastIpList"]["IpAddressType"] == original_ip_type, (
        f"expected IpAddressType {original_ip_type!r} after a valid update, "
        f"got {updated['AnycastIpList']['IpAddressType']!r}"
    )


# ===== helpers =====


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _assert_entitlement_gate_withheld(ctx, cf, attempted_name: str, code: str) -> None:
    """The create prerequisite is refused before any list exists to run the Update
    scenario against -- assert that refusal itself: the specific code already known
    (`code`), no list allocated under the attempted name, and a sibling create call
    unaffected by the zero-default quota still working."""
    existing = cf.list_anycast_ip_lists(MaxItems=100)["AnycastIpLists"]["Items"]
    assert not any(item["Name"] == attempted_name for item in existing), (
        f"CreateAnycastIpList raised {code!r} yet {attempted_name!r} is listed"
    )

    kvs_name = ctx.unique_name("sim2real-anycast-upd-control-")
    kvs = cf.create_key_value_store(Name=kvs_name)["KeyValueStore"]
    ctx.on_cleanup(lambda: _delete_key_value_store_best_effort(cf, kvs_name))
    assert kvs["Name"] == kvs_name, (
        f"sibling create_key_value_store {kvs_name!r} failed too; the account/credentials "
        "are unhealthy in general, not just anycast-entitlement-gated"
    )


def _delete_key_value_store_best_effort(cf, name: str) -> None:
    try:
        etag = cf.describe_key_value_store(Name=name)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    try:
        cf.delete_key_value_store(Name=name, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
