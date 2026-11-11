"""op-contract-deleteOriginAccessControl."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteOriginAccessControl"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteOriginAccessControl: a stale IfMatch is rejected distinctly, and a
    correct delete removes the OAC so Get reports NotFound."""
    cf = ctx.client("cloudfront")

    created = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-oac-"),
            "Description": "sim2real behavioral check",
            "SigningProtocol": "sigv4",
            "SigningBehavior": "always",
            "OriginAccessControlOriginType": "s3",
        }
    )
    oac_id = created["OriginAccessControl"]["Id"]
    etag = created["ETag"]

    def _cleanup(oac_id=oac_id):
        try:
            fresh = cf.get_origin_access_control(Id=oac_id)
            cf.delete_origin_access_control(Id=oac_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
                raise

    ctx.on_cleanup(_cleanup)

    # error boundary: garbled IfMatch while the OAC still exists
    bad_code, bad_message = _error(
        lambda: cf.delete_origin_access_control(Id=oac_id, IfMatch='"bogus-etag"')
    )
    assert bad_code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {bad_code}"
    assert bad_message == "The If-Match version is missing or not valid for the resource.", (
        f"expected the exact refusal message, got {bad_message!r}"
    )

    # the rejected delete must not have taken effect
    still_there = cf.get_origin_access_control(Id=oac_id)
    assert still_there["OriginAccessControl"]["Id"] == oac_id, (
        "a delete rejected for a stale IfMatch must not have removed the OAC"
    )

    # success path
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
    gone_code, gone_message = _error(lambda: cf.get_origin_access_control(Id=oac_id))
    assert gone_code == "NoSuchOriginAccessControl", (
        f"expected NoSuchOriginAccessControl, got {gone_code}"
    )
    assert gone_message == "The specified origin access control does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )

    # a mutation on the now-dead id fails the same way, not with a stale-etag error
    redelete_code, redelete_message = _error(lambda: cf.delete_origin_access_control(Id=oac_id, IfMatch=etag))
    assert redelete_code == "NoSuchOriginAccessControl", (
        f"expected a second delete on the dead id to report NoSuchOriginAccessControl, got {redelete_code}"
    )
    assert redelete_message == "The specified origin access control does not exist.", (
        f"expected the exact refusal message, got {redelete_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
