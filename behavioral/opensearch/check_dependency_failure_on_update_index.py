"""dependency-failure-on-update-index."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dependency-failure-on-update-index"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIndex on an OpenSearch_2.11 domain fails with ValidationException and the exact software-version
    message, while the same call on the latest version fails with DependencyFailureException; the gated
    domain still resolves through DescribeDomain.
    """
    aos = ctx.client("opensearch")
    index_name = "sim2real-depfail-idx"
    cluster_config = {
        "InstanceType": "t3.small.search",
        "InstanceCount": 1,
        "DedicatedMasterEnabled": False,
        "ZoneAwarenessEnabled": False,
    }
    ebs_options = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}

    domain_name = _compliant_domain_name(ctx, "sim2real-depfail")
    aos.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig=cluster_config,
        EBSOptions=ebs_options,
        TagList=[{"Key": "sim2real", "Value": "dependency-failure-on-update-index"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_domain(DomainName=domain_name)))

    refusal_code, refusal_message = _error(
        lambda: aos.update_index(
            DomainName=domain_name,
            IndexName=index_name,
            IndexSchema={"settings": {"index": {"number_of_shards": 1}}},
        )
    )
    assert (refusal_code, refusal_message) == ("ValidationException", (
        "Automatic Semantic Enrichment feature is not supported on this software version."
    )), (
        f"expected ValidationException with AWS's exact software-version-gate message, got {(refusal_code, refusal_message)!r}"
    )

    # Positive control: the identical call shape against a domain on a version that DOES
    # support the gated feature must not hit the same version-gate wall -- it progresses past
    # that validation to the cluster dependency, which a still-provisioning domain cannot serve
    # (DependencyFailureException, 424). Without this, a target that hardcodes the version-gate
    # error for every UpdateIndex call, regardless of engine version, would still pass.
    control_version = _latest_opensearch_version(ctx)
    control_domain = _compliant_domain_name(ctx, "sim2real-depfail-ctl")
    aos.create_domain(
        DomainName=control_domain,
        EngineVersion=control_version,
        ClusterConfig=cluster_config,
        EBSOptions=ebs_options,
        TagList=[{"Key": "sim2real", "Value": "dependency-failure-on-update-index"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_domain(DomainName=control_domain)))

    ctl_refusal_code, ctl_refusal_message = _error(
        lambda: aos.update_index(
            DomainName=control_domain,
            IndexName=index_name,
            IndexSchema={"settings": {"index": {"number_of_shards": 1}}},
        )
    )
    assert (ctl_refusal_code, ctl_refusal_message) == (
        "DependencyFailureException",
        "The domain is not available now, please try again later.",
    ), (
        f"expected the version-gate rejection to clear on {control_version} and the call to "
        f"stop at the unavailable-cluster dependency instead, got {(ctl_refusal_code, ctl_refusal_message)!r}"
    )

    # Terminal read: an independent control-plane call against the very same gated domain,
    # which does not depend on the gated feature, still succeeds -- proving the domain is
    # real and reachable at the API layer, and the rejection above is specifically about
    # the version-gated feature, not a generic or access-denied failure.
    control = aos.describe_domain(DomainName=domain_name)["DomainStatus"]
    assert control["DomainName"] == domain_name, (
        f"expected DescribeDomain to still resolve {domain_name!r}, got {control!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so an emulator accepting what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _latest_opensearch_version(ctx) -> str:
    aos = ctx.client("opensearch")
    versions: list[str] = []
    resp = aos.list_versions(MaxResults=100)
    versions.extend(resp.get("Versions", []))
    while resp.get("NextToken"):
        resp = aos.list_versions(MaxResults=100, NextToken=resp["NextToken"])
        versions.extend(resp.get("Versions", []))

    def key(v: str) -> tuple[int, int]:
        major, minor = v.split("_", 1)[1].split(".")
        return (int(major), int(minor))

    os_versions = sorted((v for v in versions if v.startswith("OpenSearch_")), key=key)
    if not os_versions:
        raise AssertionError(f"no OpenSearch_* engine versions in ListVersions response: {versions!r}")
    return os_versions[-1]


def _compliant_domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:28]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
