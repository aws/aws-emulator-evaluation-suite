"""tag-value-unicode-round-trip-on-acme-endpoint."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip-on-acme-endpoint"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A unicode/emoji tag value written via TagResource on an ACME endpoint must come back
    byte-for-byte identical from ListTagsForResource -- not re-encoded, truncated, or
    mangled by an emulator that treats tag values as plain ASCII."""
    acm = ctx.client("acm")
    _require_acme_api(acm)

    endpoint_arn = _create_active_acme_endpoint(ctx, acm)

    # ACM tag values are constrained to the standard AWS tagging character class
    # (letters, separators, numbers, and _.:/=+-@) -- symbol-category codepoints such as
    # emoji are rejected by ValidationException, so this exercises accented Latin, CJK,
    # and Arabic letters (all \p{L}) without straying into disallowed symbol codepoints.
    unicode_value = "caf\u00e9-\u4e2d\u6587-\u0645\u0631\u062d\u0628\u0627"
    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real-unicode", "Value": unicode_value}])

    tags = {t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]}
    actual = tags["sim2real-unicode"]
    assert actual == unicode_value, (
        f"tag value not byte-identical after round trip: wrote {unicode_value!r}, "
        f"ListTagsForResource returned {actual!r}"
    )


def _require_acme_api(client) -> None:
    if "CreateAcmeEndpoint" not in client.meta.service_model.operation_names:
        raise AssertionError(
            "installed botocore lacks the ACM ACME endpoint operations "
            "(CreateAcmeEndpoint/TagResource/ListTagsForResource) -- upgrade botocore/boto3 to a "
            "version that models the ACM ACME endpoint API surface"
        )


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last value={last!r}")


def _create_active_acme_endpoint(ctx, acm) -> str:
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
    )
    arn = resp["AcmeEndpointArn"]

    def _cleanup_endpoint():
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_endpoint)
    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    if status != "ACTIVE":
        raise AssertionError(f"ACME endpoint entered {status}, expected ACTIVE")
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
