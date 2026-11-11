"""data-source-config-binary-blob-round-trip."""
from __future__ import annotations

import base64
import os
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-source-config-binary-blob-round-trip"
GROUP = "representation"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A base64 blob in AddDataSource's Description and its RoleArn read back byte-identical via
    GetDataSource; after delete, GetDataSource on the name raises ValidationException."""
    opensearch = ctx.client("opensearch")
    # Data sources live on a domain; it uses the cheapest working shape and is deleted on cleanup.
    domain_name = _create_active_domain(ctx)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{_short_role_name(ctx)}"

    # A base64-encoded "credential/cert blob" -- base64's alphabet (A-Za-z0-9+/=) is a
    # subset of the characters the Description field's pattern permits, so this is a
    # legitimate way to push opaque binary-derived content through a documented string field.
    blob = base64.b64encode(os.urandom(96)).decode("ascii")

    data_source_name = _ds_name(ctx)
    _add_data_source_with_retry(
        opensearch,
        DomainName=domain_name,
        Name=data_source_name,
        DataSourceType={"S3GlueDataCatalog": {"RoleArn": role_arn}},
        Description=blob,
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: opensearch.delete_data_source(DomainName=domain_name, Name=data_source_name)
        )
    )

    got = opensearch.get_data_source(DomainName=domain_name, Name=data_source_name)
    assert got["Description"] == blob, "base64 blob in Description was not preserved byte-for-byte"
    assert got["DataSourceType"]["S3GlueDataCatalog"]["RoleArn"] == role_arn, (
        f"RoleArn not round-tripped: expected {role_arn!r}, got "
        f"{got['DataSourceType']['S3GlueDataCatalog'].get('RoleArn')!r}"
    )

    opensearch.delete_data_source(DomainName=domain_name, Name=data_source_name)
    refusal = _poll_for_error(
        lambda: opensearch.get_data_source(DomainName=domain_name, Name=data_source_name),
        "ValidationException",
    )
    # AWS rejects a deleted data source's Name as an invalid request, not a 404.
    assert refusal == ("ValidationException", f"DataSource with name {data_source_name} doesn't exist."), (
        f"GetDataSource after delete: expected ValidationException with AWS's exact message, "
        f"got {refusal!r}"
    )


def _domain_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-").lower()
    cleaned = re.sub(r"[^a-z0-9-]", "-", raw)
    truncated = cleaned[:28].rstrip("-")
    if len(truncated) < 3:
        truncated = (truncated + "dom")[:28]
    return truncated


def _ds_name(ctx) -> str:
    raw = ctx.unique_name("sim2real_ds_").lower()
    cleaned = re.sub(r"[^a-z0-9_]", "_", raw)
    truncated = cleaned[:80].rstrip("_")
    if len(truncated) < 3 or not truncated[0].isalpha():
        truncated = ("ds_" + truncated)[:80]
    return truncated


def _short_role_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-role-")
    return re.sub(r"[^A-Za-z0-9+=,.@_-]", "-", raw)[:64]


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as err:
        # A data source that is already gone surfaces as ValidationException, not
        # ResourceNotFoundException, on a subsequent delete -- see the terminal
        # assertion in run() for the same asymmetry on GetDataSource.
        if err.response.get("Error", {}).get("Code") not in (
            "ResourceNotFoundException",
            "ValidationException",
        ):
            raise


def _add_data_source_with_retry(client, timeout_s: float = 300.0, interval_s: float = 15.0, **kwargs) -> dict:
    """Retry AddDataSource on DependencyFailureException: right after the domain reports Active,
    its control plane can still need a moment before it accepts data-source calls."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return client.add_data_source(**kwargs)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "DependencyFailureException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise last_err


def _poll_for_error(fn, expected_code: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> tuple:
    """Poll fn() until it raises expected_code; return (code, message) of the last ClientError,
    or raise if the call still succeeds when the budget runs out."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            result = fn()
            last = None
        except ClientError as err:
            last = (err.response["Error"]["Code"], err.response["Error"].get("Message", ""))
            if last[0] == expected_code:
                return last
        time.sleep(interval_s)
    if last is None:
        raise AssertionError(f"expected {expected_code} within {timeout_s}s, but the call SUCCEEDED: {result!r}")
    return last


def _create_active_domain(ctx, timeout_s: float = 2400.0, interval_s: float = 30.0) -> str:
    """Create a minimal single-node domain and poll until it leaves 'Processing'.

    Domain creation typically takes 15-30 minutes, hence the generous bounded poll.
    """
    opensearch = ctx.client("opensearch")
    domain_name = _domain_name(ctx)
    opensearch.create_domain(
        DomainName=domain_name,
        # AddDataSource needs 2.13+; on 2.11 AWS rejects it with DisabledOperationException.
        EngineVersion="OpenSearch_2.13",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: opensearch.delete_domain(DomainName=domain_name)))

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if not status.get("Processing", True) and status.get("Endpoint") is not None:
            return domain_name
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
