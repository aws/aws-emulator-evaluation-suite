"""asset-filter-column-configuration-becomes-valid."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "asset-filter-column-configuration-becomes-valid"
GROUP = "data-plane"
SERVICES = ["datazone"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAssetFilter with a column configuration settles into a VALID FilterStatus.

    Column filters need an asset whose schema declares the columns, so the asset uses the built-in
    GlueTableAssetType (its GlueTableForm is catalog metadata; no live Glue table is needed)."""
    dz = ctx.client("datazone")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain = _create_domain(ctx)
    project = _create_project(ctx, domain["id"])

    database_name = ctx.unique_name("sim2real-dz-db-")
    table_name = ctx.unique_name("sim2real-dz-tbl-")
    glue_table_form = json.dumps(
        {
            "tableName": table_name,
            "region": ctx.region,
            "catalogId": account_id,
            "databaseName": database_name,
            "tableArn": f"arn:aws:glue:{ctx.region}:{account_id}:table/{database_name}/{table_name}",
            "columns": [
                {"columnName": "col1", "dataType": "string"},
                {"columnName": "col2", "dataType": "string"},
            ],
        }
    )
    asset = dz.create_asset(
        domainIdentifier=domain["id"],
        name=ctx.unique_name("sim2real-dz-asset-"),
        typeIdentifier="amazon.datazone.GlueTableAssetType",
        owningProjectIdentifier=project["id"],
        formsInput=[
            {
                "formName": "GlueTableForm",
                "typeIdentifier": "amazon.datazone.GlueTableFormType",
                "content": glue_table_form,
            }
        ],
    )
    ctx.on_cleanup(_safe(lambda: dz.delete_asset(domainIdentifier=domain["id"], identifier=asset["id"])))

    created = dz.create_asset_filter(
        domainIdentifier=domain["id"],
        assetIdentifier=asset["id"],
        name=ctx.unique_name("sim2real-dz-filter-"),
        configuration={"columnConfiguration": {"includedColumnNames": ["col1", "col2"]}},
    )
    filter_id = created["id"]
    ctx.on_cleanup(
        _safe(
            lambda: dz.delete_asset_filter(
                domainIdentifier=domain["id"], assetIdentifier=asset["id"], identifier=filter_id
            )
        )
    )

    valid_filter = _poll_until(
        lambda: dz.get_asset_filter(
            domainIdentifier=domain["id"], assetIdentifier=asset["id"], identifier=filter_id
        ),
        lambda resp: resp["status"] == "VALID",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert valid_filter["status"] == "VALID", (
        f"expected asset filter {filter_id} to settle into VALID, got {valid_filter['status']!r} "
        f"(errorMessage={valid_filter.get('errorMessage')!r})"
    )
    got_columns = set(valid_filter["configuration"]["columnConfiguration"]["includedColumnNames"])
    assert got_columns == {"col1", "col2"}, (
        f"expected includedColumnNames {{'col1', 'col2'}} to survive the round trip, got {got_columns!r}"
    )


# ===== helpers =====
def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-dz-"}


def _safe(fn, deadline_s=60.0):
    """Teardown: a resource already gone is fine; ConflictException (a dependent resource is still
    being released) is retried to a deadline; every other error raises."""
    def _wrapped():
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + deadline_s
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in ("ResourceNotFoundException", "NoSuchEntity"):
                    return
                if code != "ConflictException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last}")


def _create_domain(ctx):
    dz = ctx.client("datazone")
    role_arn = _create_domain_execution_role(ctx)
    name = ctx.unique_name("sim2real-dz-domain-")
    created = _create_domain_call(dz, name, role_arn)
    domain_id = created["id"]
    ctx.on_cleanup(
        _safe(lambda: dz.delete_domain(identifier=domain_id, cascadeDelete=True))
    )
    return _wait_domain_available(ctx, domain_id)


def _create_domain_execution_role(ctx):

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dz-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "datazone.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetContext"],
            }
        ],
    }
    role = _create_role_with_retry(iam, role_name, trust_policy)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_role_with_retry(iam, role_name, trust_policy, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    tags = [{"Key": k, "Value": v} for k, v in _mgmt_tags().items()]
    while time.monotonic() < deadline:
        try:
            return iam.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=tags
            )
        except Exception as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _create_domain_call(dz, name, role_arn, timeout_s=60.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return dz.create_domain(name=name, domainExecutionRole=role_arn, tags=_mgmt_tags())
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _wait_domain_available(ctx, domain_id, timeout_s=900.0):
    dz = ctx.client("datazone")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = dz.get_domain(identifier=domain_id)
        last = resp
        if resp["status"] == "AVAILABLE":
            return resp
        if resp["status"] == "CREATION_FAILED":
            raise AssertionError(f"domain {domain_id} creation failed: {resp}")
        time.sleep(5)
    raise AssertionError(f"domain {domain_id} did not become AVAILABLE in time: {last}")


def _create_project(ctx, domain_id, name=None, domain_unit_id=None):
    dz = ctx.client("datazone")
    name = name or ctx.unique_name("sim2real-dz-proj-")
    kwargs = {"domainIdentifier": domain_id, "name": name, "resourceTags": _mgmt_tags()}
    if domain_unit_id:
        kwargs["domainUnitId"] = domain_unit_id
    resp = dz.create_project(**kwargs)
    project_id = resp["id"]
    ctx.on_cleanup(
        _safe(
            lambda: dz.delete_project(
                domainIdentifier=domain_id, identifier=project_id, skipDeletionCheck=True
            )
        )
    )
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
