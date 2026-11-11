"""overly-permissive-storage-tier-dependency-rules."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "overly-permissive-storage-tier-dependency-rules"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology; domains bill per node-hour.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created or is already deleted."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_access_policy(ctx, domain_name: str) -> str:
    """Resource-based policy letting this account's principals use the data plane."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
        }],
    })


def _reserve_domain_name(ctx) -> str:
    """Allocate a unique in-bounds (3-28 char) domain name and pre-register its teardown."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    return domain_name


def _create_domain(ctx, domain_name: str, **overrides):
    """CreateDomain with the minimum legal topology; retries only on throttling."""
    osc = ctx.client("opensearch")
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        TagList=[{"Key": "simparity-check", "Value": CHECK}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter, then backoff on throttling.
    for attempt in range(12):
        time.sleep(random.uniform(0, 10.0) if attempt == 0 else 6.0 * (1 + attempt) + random.uniform(0, 6.0))
        try:
            return osc.create_domain(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _expect_rejection(
    ctx, what: str, expected: tuple[str, str], **overrides
):
    """Assert CreateDomain refuses these options with the exact (code, message), leaving no domain."""
    osc = ctx.client("opensearch")
    domain_name = _reserve_domain_name(ctx)
    try:
        response = _create_domain(ctx, domain_name, **overrides)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        message = exc.response.get("Error", {}).get("Message", "") or ""
        assert code == expected[0], (
            f"{what}: expected {expected[0]}, got {code}: {message}"
        )
        assert message == expected[1], (
            f"{what}: each broken link in the tier chain has its own diagnosis, so an "
            f"emulator cannot pass by mapping every tiered topology to one complaint; "
            f"expected {expected[1]!r}, got {message!r}"
        )
        # Effect absent: the refused create must not have provisioned a cluster.
        try:
            status = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
            raise AssertionError(
                f"{what}: CreateDomain was rejected but the domain exists anyway "
                f"(DomainId={status.get('DomainId')})"
            )
        except ClientError as describe_exc:
            describe_code = describe_exc.response.get("Error", {}).get("Code")
            assert describe_code == "ResourceNotFoundException", (
                f"{what}: DescribeDomain after a rejected create should be "
                f"ResourceNotFoundException, got {describe_code}"
            )
        return code, message
    raise AssertionError(
        f"{what}: CreateDomain should have been rejected but succeeded with "
        f"DomainId={response['DomainStatus'].get('DomainId')}"
    )


# UltraWarm/ColdStorage are only offered on standard instance families backed by dedicated
# cluster manager nodes, so the "valid" tiered topology has to be spelled out in full.
_WARM_CAPABLE_CLUSTER = {
    "InstanceType": "r6g.large.search",
    "InstanceCount": 2,
    "DedicatedMasterEnabled": True,
    "DedicatedMasterType": "m6g.large.search",
    "DedicatedMasterCount": 3,
    "ZoneAwarenessEnabled": False,
    "WarmEnabled": True,
    "WarmType": "ultrawarm1.medium.search",
    "WarmCount": 2,
}

# Same hot tier and same dedicated cluster manager nodes, but no warm tier at all.
_HOT_ONLY_CLUSTER = {
    "InstanceType": "r6g.large.search",
    "InstanceCount": 2,
    "DedicatedMasterEnabled": True,
    "DedicatedMasterType": "m6g.large.search",
    "DedicatedMasterCount": 3,
    "ZoneAwarenessEnabled": False,
}


def _cluster(base=None, **overrides):
    config = dict(_WARM_CAPABLE_CLUSTER if base is None else base)
    config.update(overrides)
    return config


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain enforces ColdStorage -> UltraWarm -> dedicated cluster manager nodes, each broken link with its
    own exact error, and accepts and stores the fully specified tiered topology.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ultrawarm.html
    """
    osc = ctx.client("opensearch")

    # Negative 1: cold storage with no warm tier. AWS answers with the code BaseException, which the
    # model does not declare for CreateDomain.
    _expect_rejection(
        ctx, "ColdStorage without UltraWarm",
        ("BaseException", "To use cold storage, you must have UltraWarm enabled."),
        ClusterConfig=_cluster(_HOT_ONLY_CLUSTER, ColdStorageOptions={"Enabled": True}),
    )

    # Negative 2: a warm tier with no dedicated cluster manager nodes.
    _expect_rejection(
        ctx, "UltraWarm without dedicated master nodes",
        ("ValidationException", "To use warm storage, your domain must have dedicated master nodes."),
        ClusterConfig={
            "InstanceType": "r6g.large.search",
            "InstanceCount": 2,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
            "WarmEnabled": True,
            "WarmType": "ultrawarm1.medium.search",
            "WarmCount": 2,
        },
    )

    # Negative 3: a warm tier on a burstable family that does not offer UltraWarm. AWS echoes the
    # type in its elasticsearch spelling even though the request used .search.
    _expect_rejection(
        ctx, "UltraWarm on an unsupported instance family",
        (
            "ValidationException",
            "Warm storage is not available for the t3.small.elasticsearch instance type. "
            "Select a different instance type.",
        ),
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": True,
            "DedicatedMasterType": "t3.small.search",
            "DedicatedMasterCount": 3,
            "ZoneAwarenessEnabled": False,
            "WarmEnabled": True,
            "WarmType": "ultrawarm1.medium.search",
            "WarmCount": 2,
        },
    )

    # Negative 4: WarmEnabled with a warm node count below the service minimum of 2. WarmCount
    # has no modelled range, so this bound exists only in the service's own validation.
    _expect_rejection(
        ctx, "UltraWarm with WarmCount below the minimum",
        ("ValidationException", "Warm storage node count must be between 2 and 150."),
        ClusterConfig=_cluster(WarmCount=1),
    )

    # Control: the fully-specified tiered topology is accepted and the tiers are stored.
    control_name = _reserve_domain_name(ctx)
    response = _create_domain(
        ctx, control_name,
        AccessPolicies=_account_access_policy(ctx, control_name),
        ClusterConfig=_cluster(ColdStorageOptions={"Enabled": True}),
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 20},
    )
    cluster = response["DomainStatus"].get("ClusterConfig", {})
    assert cluster.get("WarmEnabled") is True, (
        f"a valid tiered domain must report WarmEnabled=true, got {cluster}"
    )
    assert cluster.get("WarmCount") == 2, (
        f"WarmCount was not stored as requested: {cluster.get('WarmCount')}"
    )
    assert cluster.get("WarmType") == "ultrawarm1.medium.search", (
        f"WarmType was not stored as requested: {cluster.get('WarmType')}"
    )
    assert cluster.get("ColdStorageOptions", {}).get("Enabled") is True, (
        f"ColdStorageOptions was dropped: {cluster.get('ColdStorageOptions')}"
    )
    assert cluster.get("DedicatedMasterCount") == 3, (
        f"DedicatedMasterCount was not stored as requested: {cluster.get('DedicatedMasterCount')}"
    )

    # DescribeDomainConfig must agree with the create response.
    config = osc.describe_domain_config(DomainName=control_name)["DomainConfig"]
    stored = config.get("ClusterConfig", {}).get("Options", {})
    assert stored.get("WarmEnabled") is True, (
        f"DescribeDomainConfig disagrees with CreateDomain about the warm tier: {stored}"
    )

    # Delete straight away -- warm and cold nodes are separately billed, so never leave this
    # topology running any longer than the assertions need.
    _delete_domain_quietly(osc, control_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
