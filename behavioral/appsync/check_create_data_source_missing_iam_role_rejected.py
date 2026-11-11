"""create-data-source-missing-iam-role-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-data-source-missing-iam-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AWS_LAMBDA CreateDataSource without serviceRoleArn fails BadRequestException and creates
    nothing; the identical configuration with a real serviceRoleArn succeeds.
    """
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-ds-"),
        authenticationType="API_KEY",
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    lambda_config = {
        "lambdaFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:sim2real-nonexistent"
    }

    bad_ds_name = _ds_name(ctx, "bad")
    code, message = _error(
        lambda: appsync.create_data_source(
            apiId=api_id, name=bad_ds_name, type="AWS_LAMBDA", lambdaConfig=lambda_config
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Service role arn not specified.", f"expected the exact refusal message, got {message!r}"

    listed = appsync.list_data_sources(apiId=api_id)["dataSources"]
    assert all(ds["name"] != bad_ds_name for ds in listed), (
        f"a data source named {bad_ds_name!r} should not exist after the rejected create, "
        f"but found it in list_data_sources: {listed!r}"
    )
    not_found_code, not_found_message = _error(lambda: appsync.get_data_source(apiId=api_id, name=bad_ds_name))
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for the never-created data source {bad_ds_name!r}, "
        f"got {not_found_code!r}"
    )
    assert not_found_message == f"Data source {bad_ds_name} not found", (
        f"expected the exact NotFound message, got {not_found_message!r}"
    )

    role_name = ctx.unique_name("sim2real-appsync-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "appsync.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    good_ds_name = _ds_name(ctx, "good")
    ds = _create_data_source_with_retry(
        appsync,
        apiId=api_id,
        name=good_ds_name,
        type="AWS_LAMBDA",
        lambdaConfig=lambda_config,
        serviceRoleArn=role_arn,
    )
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=good_ds_name))
    assert ds["name"] == good_ds_name, f"create_data_source returned name {ds['name']!r}, expected {good_ds_name!r}"

    fetched = appsync.get_data_source(apiId=api_id, name=good_ds_name)["dataSource"]
    assert fetched["serviceRoleArn"] == role_arn, (
        f"GetDataSource for {good_ds_name!r} reports serviceRoleArn "
        f"{fetched.get('serviceRoleArn')!r}, expected {role_arn!r}"
    )
    listed_good = appsync.list_data_sources(apiId=api_id)["dataSources"]
    assert any(d["name"] == good_ds_name for d in listed_good), (
        f"{good_ds_name!r} should now appear in list_data_sources: {listed_good!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ds_name(ctx, suffix: str) -> str:
    # DataSource names must match ^[_A-Za-z][_0-9A-Za-z]*$ -- no hyphens allowed.
    raw = ctx.unique_name(f"sim2real_appsync_ds_{suffix}_")
    return re.sub(r"[^0-9A-Za-z_]", "_", raw)


def _create_data_source_with_retry(appsync, retry_seconds: float = 30.0, **kwargs):
    # A just-created IAM role is not always immediately assumable/visible to other
    # services (documented IAM eventual-consistency window); poll the actual create
    # call rather than sleeping a fixed duration.
    deadline = time.monotonic() + retry_seconds
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return appsync.create_data_source(**kwargs)["dataSource"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    assert last_exc is not None
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
