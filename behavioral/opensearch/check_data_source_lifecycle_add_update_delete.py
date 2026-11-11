"""data-source-lifecycle-add-update-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-source-lifecycle-add-update-delete"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddDataSource -> Get -> Update(Status) -> Delete round-trips against a live domain."""
    domain_name = _create_active_domain(ctx)
    osv = ctx.client("opensearch")
    role_arn = _create_es_trust_role(ctx, "es.amazonaws.com")
    ds_name = _ds_name(ctx, "gluecat")

    _add_data_source_with_retry(
        osv,
        DomainName=domain_name,
        Name=ds_name,
        DataSourceType={"S3GlueDataCatalog": {"RoleArn": role_arn}},
        Description="sim2real behavioral check data source",
    )
    ctx.on_cleanup(lambda: _safe_delete_data_source(osv, domain_name, ds_name))

    got = osv.get_data_source(DomainName=domain_name, Name=ds_name)
    assert got["Name"] == ds_name, f"expected data source name {ds_name!r}, got {got['Name']!r}"
    assert got["DataSourceType"]["S3GlueDataCatalog"]["RoleArn"] == role_arn, (
        f"expected RoleArn {role_arn!r}, got {got['DataSourceType']['S3GlueDataCatalog']['RoleArn']!r}"
    )
    assert got["Status"] == "ACTIVE", f"new data source landed in status {got['Status']!r}, not ACTIVE"

    assert ds_name in _list_data_source_names(osv, domain_name), (
        "data source missing from ListDataSources after AddDataSource"
    )

    osv.update_data_source(
        DomainName=domain_name,
        Name=ds_name,
        DataSourceType={"S3GlueDataCatalog": {"RoleArn": role_arn}},
        Status="DISABLED",
    )

    got_after_update = osv.get_data_source(DomainName=domain_name, Name=ds_name)
    assert got_after_update["Status"] == "DISABLED", (
        f"UpdateDataSource did not flip Status to DISABLED (got {got_after_update['Status']!r})"
    )

    osv.delete_data_source(DomainName=domain_name, Name=ds_name)

    deadline = time.monotonic() + 60
    while ds_name in _list_data_source_names(osv, domain_name) and time.monotonic() < deadline:
        time.sleep(3)
    assert ds_name not in _list_data_source_names(osv, domain_name), (
        "data source still listed after DeleteDataSource"
    )

    # Once a data source has been deleted, GetDataSource doesn't treat the now-unknown
    # Name as a 404: real AWS rejects it as an invalid request instead, so the terminal
    # error here is ValidationException, not ResourceNotFoundException.
    refusal_code, refusal_message = _poll_for_error(
        lambda: osv.get_data_source(DomainName=domain_name, Name=ds_name),
        "ValidationException",
        timeout_s=60,
    )
    assert (refusal_code, refusal_message) == ("ValidationException", f"DataSource with name {ds_name} doesn't exist."), (
        f"expected ValidationException with AWS's exact message, got {(refusal_code, refusal_message)!r}"
    )


def _add_data_source_with_retry(osv, timeout_s: float = 300.0, interval_s: float = 15.0, **kwargs) -> dict:
    """AddDataSource can transiently fail with DependencyFailureException ("domain is not
    available now, please try again later") for a short window right after DescribeDomain
    reports the domain as fully Active/not-Processing, because the domain's internal
    control plane needs a little longer to settle before it will accept data-source
    management calls. Retry on that specific error instead of treating it as fatal.
    """
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return osv.add_data_source(**kwargs)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "DependencyFailureException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise last_err


def _ds_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"sim2real-{prefix}-")
    return raw.replace("-", "_").lower()


def _short_domain_name(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real-{tag}-").lower()
    if len(raw) > 28:
        raw = raw[-28:]
    if not raw[0].isalpha():
        raw = "d" + raw[1:]
    return raw


def _create_active_domain(ctx, timeout_s: float = 1800.0) -> str:
    osv = ctx.client("opensearch")
    domain_name = _short_domain_name(ctx, "ds")
    osv.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(osv, domain_name))
    _wait_domain_active(osv, domain_name, timeout_s=timeout_s)
    return domain_name


def _wait_domain_active(osv, domain_name: str, timeout_s: float = 1800.0, interval_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status = osv.describe_domain(DomainName=domain_name)["DomainStatus"]
        last = status
        if status.get("Created") and not status.get("Processing") and not status.get("UpgradeProcessing"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} did not become Active within {timeout_s}s (last={last})")


def _create_es_trust_role(ctx, principal: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-osrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _list_data_source_names(osv, domain_name: str) -> set[str]:
    resp = osv.list_data_sources(DomainName=domain_name)
    return {d["Name"] for d in resp.get("DataSources", [])}


def _safe_delete_data_source(osv, domain_name: str, ds_name: str) -> None:
    try:
        osv.delete_data_source(DomainName=domain_name, Name=ds_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_domain(osv, domain_name: str) -> None:
    try:
        osv.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
