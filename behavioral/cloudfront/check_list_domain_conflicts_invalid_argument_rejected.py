"""list-domain-conflicts-invalid-argument-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-domain-conflicts-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

# Real AWS answers both domains with the same certificate refusal: the validation resource holds
# no certificate, so the refusal names the missing certificate rather than the domain string.
_NO_CERTIFICATE = (
    "There must be at least one certificate in the distribution tenant or distribution, "
    "or there must be a managed certificate request"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDomainConflicts against a distribution with no certificate covering the domain refuses both a
    malformed domain and an overlong one with InvalidArgument and the same missing-certificate message:
    the certificate is checked before the domain string."""
    cf = ctx.client("cloudfront")

    dist_id = _create_distribution(ctx, cf)
    validation_resource = {"DistributionId": dist_id}

    malformed_domain = "not a valid domain !!"
    code, message = _error(
        lambda: cf.list_domain_conflicts(
            Domain=malformed_domain, DomainControlValidationResource=validation_resource
        )
    )
    assert code == "InvalidArgument", code
    expected = _NO_CERTIFICATE
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A syntactically well-formed domain that exceeds CloudFront's label-length limit gets the
    # same refusal: the missing certificate is checked before the domain string.
    overlong_domain = ("a" * 250) + ".example.com"
    overlong_code, overlong_message = _error(
        lambda: cf.list_domain_conflicts(
            Domain=overlong_domain, DomainControlValidationResource=validation_resource
        )
    )
    assert overlong_code == "InvalidArgument", overlong_code
    expected = _NO_CERTIFICATE
    assert overlong_message == expected, f"expected message {expected!r}, got {overlong_message!r}"


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_distribution(ctx, cf):
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-caller-"),
        "Comment": "sim2real behavioral check",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "www.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # Managed-CachingOptimized
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real:check", "Value": CHECK}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    return dist_id


def _delete_distribution(cf, dist_id: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    # Distribution changes typically take a few minutes to propagate; see
    # https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/HowCloudFrontWorks.html
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        if got["Distribution"]["Status"] == "Deployed":
            etag = got["ETag"]
            break
        time.sleep(interval_s)
    if etag is None:
        raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
