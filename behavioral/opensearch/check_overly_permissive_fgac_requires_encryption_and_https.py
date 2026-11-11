"""overly-permissive-fgac-requires-encryption-and-https."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "overly-permissive-fgac-requires-encryption-and-https"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology. Domains bill per node-hour and leaked domains were a real
# cost-leak class, so every domain here is the cheapest legal cluster (one t3.small.search data
# node, no dedicated cluster manager nodes, no zone awareness, minimum gp3 volume) and teardown is registered
# BEFORE the create call. This check never waits for Active: every assertion is on a synchronous
# CreateDomain rejection, and the single control domain is deleted straight out of Processing.
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
    for attempt in range(12):
        if attempt == 0:
            time.sleep(random.uniform(0, 10.0))
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


_ADMIN_USER = "sim2realadmin"
# Meets the FGAC admin-password policy (upper, lower, digit, symbol, >= 8 chars) so the
# password is never what the negative steps are actually tripping over.
_ADMIN_PASSWORD = "Sim2Real-Fgac-Pw9!"
_ENCRYPTION = {"Enabled": True}
_NODE_TO_NODE = {"Enabled": True}
_HTTPS = {"EnforceHTTPS": True, "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"}


def _advanced_security():
    return {
        "Enabled": True,
        "InternalUserDatabaseEnabled": True,
        "MasterUserOptions": {
            "MasterUserName": _ADMIN_USER,
            "MasterUserPassword": _ADMIN_PASSWORD,
        },
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain with fine-grained access control is rejected without encryption at rest, node-to-node
    encryption or EnforceHTTPS, provisioning no domain; with all three it is accepted, without echoing
    the admin password, and DescribeDomainConfig reports it enabled.
    """
    osc = ctx.client("opensearch")

    # Negative 1: FGAC without encryption at rest.
    _, message = _expect_rejection(
        ctx, "FGAC without EncryptionAtRest",
        AdvancedSecurityOptions=_advanced_security(),
        NodeToNodeEncryptionOptions=dict(_NODE_TO_NODE),
        DomainEndpointOptions=dict(_HTTPS),
    )
    assert "encryption" in message.lower(), (
        f"rejection must name the missing encryption-at-rest requirement, got {message!r}"
    )

    # Negative 2: FGAC without node-to-node encryption.
    _, message = _expect_rejection(
        ctx, "FGAC without NodeToNodeEncryption",
        AdvancedSecurityOptions=_advanced_security(),
        EncryptionAtRestOptions=dict(_ENCRYPTION),
        DomainEndpointOptions=dict(_HTTPS),
    )
    assert "node" in message.lower() or "encryption" in message.lower(), (
        f"rejection must name the missing node-to-node encryption requirement, got {message!r}"
    )

    # Negative 3: FGAC without EnforceHTTPS.
    _, message = _expect_rejection(
        ctx, "FGAC without EnforceHTTPS",
        AdvancedSecurityOptions=_advanced_security(),
        EncryptionAtRestOptions=dict(_ENCRYPTION),
        NodeToNodeEncryptionOptions=dict(_NODE_TO_NODE),
        DomainEndpointOptions={"EnforceHTTPS": False},
    )
    assert "https" in message.lower() or "tls" in message.lower(), (
        f"rejection must name the missing HTTPS requirement, got {message!r}"
    )

    # Negative 4: the internal user database is on but no admin user is supplied.
    _expect_rejection(
        ctx, "InternalUserDatabaseEnabled without MasterUserOptions",
        AdvancedSecurityOptions={"Enabled": True, "InternalUserDatabaseEnabled": True},
        EncryptionAtRestOptions=dict(_ENCRYPTION),
        NodeToNodeEncryptionOptions=dict(_NODE_TO_NODE),
        DomainEndpointOptions=dict(_HTTPS),
    )

    # Control: all three co-requirements satisfied -> accepted, and the stored configuration
    # actually reflects FGAC (not silently dropped).
    control_name = _reserve_domain_name(ctx)
    response = _create_domain(
        ctx, control_name,
        AccessPolicies=_account_access_policy(ctx, control_name),
        AdvancedSecurityOptions=_advanced_security(),
        EncryptionAtRestOptions=dict(_ENCRYPTION),
        NodeToNodeEncryptionOptions=dict(_NODE_TO_NODE),
        DomainEndpointOptions=dict(_HTTPS),
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    status = response["DomainStatus"]
    advanced = status.get("AdvancedSecurityOptions", {})
    assert advanced.get("Enabled") is True, (
        f"a fully-specified FGAC domain must report AdvancedSecurityOptions.Enabled=true, "
        f"got {advanced}"
    )
    assert advanced.get("InternalUserDatabaseEnabled") is True, (
        f"InternalUserDatabaseEnabled was dropped: {advanced}"
    )
    assert status.get("EncryptionAtRestOptions", {}).get("Enabled") is True, (
        f"EncryptionAtRestOptions was dropped: {status.get('EncryptionAtRestOptions')}"
    )
    assert status.get("NodeToNodeEncryptionOptions", {}).get("Enabled") is True, (
        f"NodeToNodeEncryptionOptions was dropped: {status.get('NodeToNodeEncryptionOptions')}"
    )
    assert status.get("DomainEndpointOptions", {}).get("EnforceHTTPS") is True, (
        f"EnforceHTTPS was dropped: {status.get('DomainEndpointOptions')}"
    )
    # The admin password must never be echoed back.
    assert "MasterUserPassword" not in json.dumps(advanced), (
        "CreateDomain echoed the FGAC admin password back to the caller"
    )

    # DescribeDomainConfig must agree with the create response.
    config = osc.describe_domain_config(DomainName=control_name)["DomainConfig"]
    stored = config.get("AdvancedSecurityOptions", {}).get("Options", {})
    assert stored.get("Enabled") is True, (
        f"DescribeDomainConfig disagrees with CreateDomain about FGAC: {stored}"
    )

    # Delete straight away -- no need to reach Active, and an idle domain bills per hour.
    _delete_domain_quietly(osc, control_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
