"""op-contract-listCloudFrontOriginAccessIdentities."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listCloudFrontOriginAccessIdentities"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCloudFrontOriginAccessIdentities returns a well-shaped, freshly-created OAI; a bad MaxItems yields InvalidArgument."""
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-oai-")
    created = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={
            "CallerReference": ref,
            "Comment": "sim2real behavioral check",
        }
    )
    oai_id = created["CloudFrontOriginAccessIdentity"]["Id"]
    ctx.on_cleanup(lambda: _delete_oai(cf, oai_id))

    resp = cf.list_cloud_front_origin_access_identities()
    body = resp["CloudFrontOriginAccessIdentityList"]
    assert isinstance(body["Quantity"], int) and body["Quantity"] > 0, (
        f"expected a positive int Quantity, got {body.get('Quantity')!r}"
    )
    ids = [item["Id"] for item in body["Items"]]
    assert oai_id in ids, "freshly created OAI should be visible in the list"

    code, msg = _error(lambda: cf.list_cloud_front_origin_access_identities(MaxItems="not-a-number"))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code}"
    assert msg == "MaxItems must be a non-zero positive integer.", f"unexpected InvalidArgument message: {msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_oai(cf, oai_id):
    cur = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=cur["ETag"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
