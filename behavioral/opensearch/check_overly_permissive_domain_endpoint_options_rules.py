"""overly-permissive-domain-endpoint-options-rules."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "overly-permissive-domain-endpoint-options-rules"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology. Domains bill per node-hour and leaked domains were a real
# cost-leak class, so every domain here is the cheapest legal cluster and teardown is registered
# BEFORE the create call. This check never waits for Active: every assertion is on a synchronous
# CreateDomain rejection, and the control domains are deleted straight out of Processing.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted."""
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
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter, then backoff on throttling.
    time.sleep(random.uniform(0, 10.0))
    for attempt in range(12):
        try:
            return osc.create_domain(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _expect_rejection(ctx, what: str, **overrides):
    """Assert CreateDomain refuses these options, and that NO domain is left behind.

    Returns (error_code, error_message) so the caller can assert on the specific complaint.
    """
    osc = ctx.client("opensearch")
    domain_name = _reserve_domain_name(ctx)
    try:
        response = _create_domain(ctx, domain_name, **overrides)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        message = exc.response.get("Error", {}).get("Message", "") or ""
        assert code == "ValidationException", (
            f"{what}: expected ValidationException, got {code}: {message}"
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


# The TLSSecurityPolicy enum as modelled. botocore does NOT enforce enum traits client-side, so
# an out-of-enum value really does reach the service and the service really is what rejects it.
_TLS_POLICIES = (
    "Policy-Min-TLS-1-0-2019-07",
    "Policy-Min-TLS-1-2-2019-07",
    "Policy-Min-TLS-1-2-PFS-2023-10",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain rejects an unknown TLSSecurityPolicy, a custom endpoint without a hostname and one without
    a certificate, provisioning no domain, while EnforceHTTPS with Policy-Min-TLS-1-2-2019-07 is accepted
    and echoed by DescribeDomainConfig.
    """
    osc = ctx.client("opensearch")

    # Negative 1: a TLS policy string outside the modelled enum.
    _, message = _expect_rejection(
        ctx, "out-of-enum TLSSecurityPolicy",
        DomainEndpointOptions={
            "EnforceHTTPS": True,
            "TLSSecurityPolicy": "Policy-Min-TLS-9-9-2099-01",
        },
    )
    assert "tls" in message.lower() or "policy" in message.lower(), (
        f"rejection must name the bad TLS policy, got {message!r}"
    )

    # Negative 2: a custom endpoint switched on with no hostname behind it.
    _, message = _expect_rejection(
        ctx, "CustomEndpointEnabled without CustomEndpoint",
        DomainEndpointOptions={
            "EnforceHTTPS": True,
            "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07",
            "CustomEndpointEnabled": True,
        },
    )
    assert "endpoint" in message.lower(), (
        f"rejection must name the missing custom endpoint, got {message!r}"
    )

    # Negative 3: a custom endpoint hostname with no ACM certificate to serve it.
    _, message = _expect_rejection(
        ctx, "CustomEndpoint without CustomEndpointCertificateArn",
        DomainEndpointOptions={
            "EnforceHTTPS": True,
            "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07",
            "CustomEndpointEnabled": True,
            "CustomEndpoint": "search.sim2real-behav.example.com",
        },
    )
    assert "certificate" in message.lower() or "arn" in message.lower(), (
        f"rejection must name the missing certificate, got {message!r}"
    )

    # Negative 4: a syntactically impossible custom endpoint hostname.
    _expect_rejection(
        ctx, "malformed CustomEndpoint hostname",
        DomainEndpointOptions={
            "EnforceHTTPS": True,
            "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07",
            "CustomEndpointEnabled": True,
            "CustomEndpoint": "not a hostname",
            "CustomEndpointCertificateArn": (
                f"arn:aws:acm:{ctx.region}:"
                f"{ctx.client('sts').get_caller_identity()['Account']}:certificate/"
                "00000000-0000-0000-0000-000000000000"
            ),
        },
    )

    # Control: a well-formed configuration is accepted and stored verbatim.
    control_name = _reserve_domain_name(ctx)
    response = _create_domain(
        ctx, control_name,
        AccessPolicies=_account_access_policy(ctx, control_name),
        DomainEndpointOptions={
            "EnforceHTTPS": True,
            "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07",
        },
    )
    endpoint_options = response["DomainStatus"].get("DomainEndpointOptions", {})
    assert endpoint_options.get("EnforceHTTPS") is True, (
        f"EnforceHTTPS was dropped by CreateDomain: {endpoint_options}"
    )
    assert endpoint_options.get("TLSSecurityPolicy") == "Policy-Min-TLS-1-2-2019-07", (
        f"TLSSecurityPolicy was not stored as requested: {endpoint_options}"
    )

    config = osc.describe_domain_config(DomainName=control_name)["DomainConfig"]
    stored = config.get("DomainEndpointOptions", {}).get("Options", {})
    assert stored.get("EnforceHTTPS") is True, (
        f"DescribeDomainConfig disagrees with CreateDomain about EnforceHTTPS: {stored}"
    )
    assert stored.get("TLSSecurityPolicy") == "Policy-Min-TLS-1-2-2019-07", (
        f"DescribeDomainConfig disagrees about TLSSecurityPolicy: {stored}"
    )
    _delete_domain_quietly(osc, control_name)

    # Control: when DomainEndpointOptions is omitted the service still materialises a concrete,
    # in-enum policy rather than leaving the field empty. (The exact default has changed over
    # time, so assert membership in the enum, not one specific value.)
    default_name = _reserve_domain_name(ctx)
    response = _create_domain(
        ctx, default_name, AccessPolicies=_account_access_policy(ctx, default_name)
    )
    defaults = response["DomainStatus"].get("DomainEndpointOptions", {})
    assert defaults.get("TLSSecurityPolicy") in _TLS_POLICIES, (
        "an omitted DomainEndpointOptions must still be defaulted to a real TLS policy, got "
        f"{defaults.get('TLSSecurityPolicy')!r} (expected one of {_TLS_POLICIES})"
    )
    assert isinstance(defaults.get("EnforceHTTPS"), bool), (
        f"EnforceHTTPS must be defaulted to a concrete boolean, got {defaults}"
    )
    _delete_domain_quietly(osc, default_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
