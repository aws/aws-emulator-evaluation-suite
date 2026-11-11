"""data-source-lifecycle."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "data-source-lifecycle"
GROUP = 'data-source'
SERVICES = ['opensearch']

FEATURE_ENGINE_VERSION = 'OpenSearch_2.19'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


# Named in the failure detail when a state machine the target accepted never converges, so the
# failure reads as a control-plane convergence failure rather than a connection error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state: a state the target
    accepted and then never reached within the budget. Every target polls the same terminal
    condition under the same budget, so the verdict is identical on all of them.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


def _create_domain(ctx, osc, domain_name, *, engine_version) -> dict:
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=engine_version,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    for _attempt in range(12):
        try:
            resp = osc.create_domain(**kwargs)
            break
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still throttled after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))
    return resp["DomainStatus"]


def _wait_domain_active(ctx, osc, domain_name, timeout_s: float = 1450) -> dict:
    """Poll until Processing=False and Created=True. A real domain needs 10-20 min to go
    Active; every target polls the same terminal condition under the same budget.
    """
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(2)
    raise _never_ready(f"domain {domain_name} never became Active within {budget}s")


def _create_service_role(ctx, iam, trust_service, managed_policy_arns=None) -> str:
    """Create a minimal IAM role trusted by trust_service; return its ARN. IAM's own replication
    is eventually consistent, so the caller retries its first use of this ARN for a bounded
    window instead of this helper guessing a fixed propagation delay."""
    role_name = ctx.unique_name("sim2real-behav-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup_role(rn=role_name):
        try:
            attached = iam.list_attached_role_policies(RoleName=rn)
            for pol in attached.get("AttachedPolicies", []):
                try:
                    iam.detach_role_policy(RoleName=rn, PolicyArn=pol["PolicyArn"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
            iam.delete_role(RoleName=rn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _add_data_source_with_retry(osc, timeout_s: float = 60.0, interval_s: float = 5.0, **kwargs) -> dict:
    """AddDataSource can fail while the IAM role just created for it (and its just-attached
    managed policy) has not yet propagated through IAM's eventually-consistent replication.
    Retry for a bounded window instead of guessing a fixed propagation delay; a permanent
    failure still surfaces once the deadline passes, unchanged."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return osc.add_data_source(**kwargs)
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise last_err


def _refusal(fn) -> "tuple[str, str]":
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS raises
    -- this is used only where success is never legitimate."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_for_refusal(fn, *, expected_code: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> "tuple[str, str]":
    """Poll fn() until it raises expected_code and return that (code, message). A transient
    success while the deletion propagates is tolerated inside the window; still succeeding (or
    failing differently) at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ("succeeded", fn())
        except ClientError as exc:
            last = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
            if last[0] == expected_code:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"expected {expected_code} within {timeout_s}s, last outcome {last!r}")


def _delete_data_source_if_present(osc, domain, name) -> None:
    """Teardown: the check deletes the data source itself, so a second delete that finds it
    already gone (ValidationException) is the expected outcome."""
    try:
        osc.delete_data_source(DomainName=domain, Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ValidationException":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddDataSource->GetDataSource->UpdateDataSource->ListDataSources->
    DeleteDataSource cycle on a live domain; GetDataSource and UpdateDataSource
    on the deleted Name both raise ValidationException afterward."""
    osc = ctx.client("opensearch")
    iam = ctx.client("iam")

    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain, engine_version=FEATURE_ENGINE_VERSION)
    _wait_domain_active(ctx, osc, domain)

    role_arn = _create_service_role(
        ctx, iam, "opensearchservice.amazonaws.com",
        ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"],
    )

    # AddDataSource Name uses pattern [a-z][a-z0-9_]+ -- no hyphens allowed.
    name = ctx.unique_name("sim2real_behav_ds_").replace("-", "_")
    add_resp = _add_data_source_with_retry(
        osc,
        DomainName=domain,
        Name=name,
        DataSourceType={"S3GlueDataCatalog": {"RoleArn": role_arn}},
        Description="sim2real behavioral data source",
    )
    ctx.on_cleanup(lambda: _delete_data_source_if_present(osc, domain, name))
    assert "Message" in add_resp, f"AddDataSource response missing Message: {add_resp!r}"

    got = osc.get_data_source(DomainName=domain, Name=name)
    assert got["Name"] == name, f"expected Name {name!r}, got {got.get('Name')!r}"
    assert "S3GlueDataCatalog" in got["DataSourceType"], (
        f"expected S3GlueDataCatalog in DataSourceType, got {got.get('DataSourceType')!r}"
    )
    assert got["Status"] == "ACTIVE", f"expected a freshly added data source ACTIVE, got {got.get('Status')!r}"

    osc.update_data_source(
        DomainName=domain,
        Name=name,
        DataSourceType={"S3GlueDataCatalog": {"RoleArn": role_arn}},
        Description="sim2real behavioral data source updated",
    )
    got2 = osc.get_data_source(DomainName=domain, Name=name)
    assert got2["Description"] == "sim2real behavioral data source updated", (
        f"UpdateDataSource did not change Description, got {got2.get('Description')!r}"
    )

    listed = {d["Name"] for d in osc.list_data_sources(DomainName=domain)["DataSources"]}
    assert name in listed, f"{name!r} missing from ListDataSources after AddDataSource: {listed!r}"

    osc.delete_data_source(DomainName=domain, Name=name)

    get_refusal = _poll_for_refusal(
        lambda: osc.get_data_source(DomainName=domain, Name=name),
        expected_code="ValidationException",
        timeout_s=60,
    )
    assert get_refusal == ("ValidationException", f"DataSource with name {name} doesn't exist."), (
        f"expected GetDataSource on the deleted Name to fail with ValidationException and AWS's "
        f"exact message, got {get_refusal!r}"
    )

    update_refusal = _refusal(
        lambda: osc.update_data_source(
            DomainName=domain,
            Name=name,
            DataSourceType={"S3GlueDataCatalog": {"RoleArn": role_arn}},
        )
    )
    assert update_refusal == ("ValidationException", f"DataSource with name {name} doesn't exist."), (
        f"expected UpdateDataSource on the deleted Name to fail with ValidationException and "
        f"AWS's exact message, got {update_refusal!r}"
    )

    listed_after = {d["Name"] for d in osc.list_data_sources(DomainName=domain).get("DataSources", [])}
    assert name not in listed_after, f"{name!r} still listed after DeleteDataSource: {listed_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
