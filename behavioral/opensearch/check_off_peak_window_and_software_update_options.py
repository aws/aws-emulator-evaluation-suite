"""off-peak-window-and-software-update-options."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "off-peak-window-and-software-update-options"
GROUP = 'maintenance-scheduling'
SERVICES = ['opensearch']

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology, since domains bill per node-hour; teardown is registered
# before the create. Nothing waits for Active: the control domain is deleted while Processing.
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
        TagList=[{"Key": "simparity-check", "Value": CHECK}],
    )
    kwargs.update(overrides)
    for attempt in range(12):
        # CreateDomain is aggressively rate limited per account: jitter before the first
        # attempt too, so concurrent runs against the same account don't all land at once.
        time.sleep(random.uniform(0, 10.0) if attempt == 0 else 0)
        try:
            return osc.create_domain(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _expect_rejection(ctx, what: str, expected_message: str, **overrides):
    """Assert CreateDomain refuses these options with an exact message, and that NO domain
    is left behind.

    Returns (error_code, error_message) so the caller can assert further.
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
        assert message == expected_message, (
            f"{what}: the refusal must name its own reason so a caller can tell one bad "
            f"window from another; expected {expected_message!r}, got {message!r}"
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


# 02:30 local -- a legal window start.
_WINDOW = {"WindowStartTime": {"Hours": 2, "Minutes": 30}}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain rejects an off-peak window hour above 23 or minute above 59, and any request
    disabling the window, with exact messages; a legal window plus AutoSoftwareUpdateEnabled is
    stored and reported by CreateDomain, DescribeDomainConfig and DescribeDomains.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/off-peak.html
    """
    osc = ctx.client("opensearch")

    # botocore validates only the range minimum, so the upper-bound violations reach the service.
    _expect_rejection(
        ctx, "OffPeakWindow with Hours=25",
        "1 validation error detected: Value '25' at "
        "'offPeakWindowOptions.offPeakWindow.windowStartTime.hours' failed to satisfy "
        "constraint: Member must have value less than or equal to 23",
        OffPeakWindowOptions={
            "Enabled": True,
            "OffPeakWindow": {"WindowStartTime": {"Hours": 25, "Minutes": 0}},
        },
    )

    _expect_rejection(
        ctx, "OffPeakWindow with Minutes=99",
        "1 validation error detected: Value '99' at "
        "'offPeakWindowOptions.offPeakWindow.windowStartTime.minutes' failed to satisfy "
        "constraint: Member must have value less than or equal to 59",
        OffPeakWindowOptions={
            "Enabled": True,
            "OffPeakWindow": {"WindowStartTime": {"Hours": 2, "Minutes": 99}},
        },
    )

    # The window is mandatory, so disabling it is refused even with a legal window supplied.
    window_required = "An off-peak window is required for a domain and cannot be disabled."
    _expect_rejection(
        ctx, "OffPeakWindowOptions with Enabled=False",
        window_required,
        OffPeakWindowOptions={"Enabled": False, "OffPeakWindow": dict(_WINDOW)},
    )

    _expect_rejection(
        ctx, "AutoSoftwareUpdateEnabled with the off-peak window disabled",
        window_required,
        OffPeakWindowOptions={"Enabled": False},
        SoftwareUpdateOptions={"AutoSoftwareUpdateEnabled": True},
    )

    control_name = _reserve_domain_name(ctx)
    response = _create_domain(
        ctx, control_name,
        AccessPolicies=_account_access_policy(ctx, control_name),
        OffPeakWindowOptions={"Enabled": True, "OffPeakWindow": dict(_WINDOW)},
        SoftwareUpdateOptions={"AutoSoftwareUpdateEnabled": True},
    )
    status = response["DomainStatus"]

    off_peak = status.get("OffPeakWindowOptions", {})
    assert off_peak.get("Enabled") is True, (
        f"OffPeakWindowOptions.Enabled was dropped by CreateDomain: {off_peak}"
    )
    start = off_peak.get("OffPeakWindow", {}).get("WindowStartTime", {})
    assert start.get("Hours") == 2 and start.get("Minutes") == 30, (
        f"the requested window start time was not stored: {start} (expected 02:30)"
    )

    software = status.get("SoftwareUpdateOptions", {})
    assert software.get("AutoSoftwareUpdateEnabled") is True, (
        f"AutoSoftwareUpdateEnabled was dropped by CreateDomain: {software}"
    )

    # The per-option Status envelope is how callers tell a pending change from an applied one.
    config = osc.describe_domain_config(DomainName=control_name)["DomainConfig"]
    stored_window = config.get("OffPeakWindowOptions", {})
    assert "Options" in stored_window and "Status" in stored_window, (
        f"OffPeakWindowOptions must come back wrapped in Options/Status, got {stored_window}"
    )
    stored_start = (
        stored_window["Options"].get("OffPeakWindow", {}).get("WindowStartTime", {})
    )
    assert stored_start.get("Hours") == 2 and stored_start.get("Minutes") == 30, (
        f"DescribeDomainConfig disagrees with CreateDomain about the window: {stored_start}"
    )
    stored_software = config.get("SoftwareUpdateOptions", {})
    assert stored_software.get("Options", {}).get("AutoSoftwareUpdateEnabled") is True, (
        f"DescribeDomainConfig disagrees about AutoSoftwareUpdateEnabled: {stored_software}"
    )
    assert stored_software.get("Status", {}).get("UpdateVersion") is not None, (
        f"per-option Status.UpdateVersion missing, so config versioning is not modelled: "
        f"{stored_software}"
    )

    batch = osc.describe_domains(DomainNames=[control_name])["DomainStatusList"]
    assert len(batch) == 1, f"DescribeDomains should return exactly one domain, got {batch}"
    batch_window = batch[0].get("OffPeakWindowOptions", {}).get("OffPeakWindow", {})
    assert batch_window.get("WindowStartTime", {}).get("Hours") == 2, (
        f"DescribeDomains disagrees with DescribeDomain about the window: {batch_window}"
    )

    # Delete straight away; an idle domain bills per hour.
    _delete_domain_quietly(osc, control_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
