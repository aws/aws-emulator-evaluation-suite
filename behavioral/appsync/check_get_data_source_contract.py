"""op-contract-get-data-source."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-data-source"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_MALFORMED_API_ID = "sim2real-missing-api-id-0000"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDataSource returns the created data source and 404s a missing name; an unresolvable apiId
    (garbage or one mutated character) is BadRequestException; after delete, get 404s and update fails."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    ds_name = _ident(ctx, "ds")

    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: _delete_ds_if_present(appsync, api_id, ds_name))

    resp = appsync.get_data_source(apiId=api_id, name=ds_name)
    ds = resp["dataSource"]
    assert ds["name"] == ds_name, f"expected name {ds_name!r}, got {ds['name']!r}"
    assert ds["type"] == "NONE", f"expected type NONE, got {ds['type']!r}"
    assert ds["dataSourceArn"].endswith(f"/datasources/{ds_name}"), (
        f"expected dataSourceArn to end with /datasources/{ds_name}, got {ds['dataSourceArn']!r}"
    )

    # Distinct error boundary: unknown data source name under a real apiId.
    code, code_msg = _error(lambda: appsync.get_data_source(apiId=api_id, name="does_not_exist_ds"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert code_msg == "Data source does_not_exist_ds not found", f"unexpected message: {code_msg!r}"

    # An apiId that does not resolve to a live API is BadRequestException, never
    # NotFoundException, both for a single mutated character of the real (still-live) apiId and
    # for a garbage string: the miss does not tell "almost right" from "not an apiId at all".
    last = api_id[-1]
    near_miss_api_id = api_id[:-1] + ("0" if last != "0" else "1")
    code2, code2_msg = _error(lambda: appsync.get_data_source(apiId=near_miss_api_id, name=ds_name))
    assert code2 == "BadRequestException", f"expected BadRequestException, got {code2}"
    assert code2_msg == f"Invalid API ID {near_miss_api_id}", f"unexpected message: {code2_msg!r}"

    code2b, code2b_msg = _error(lambda: appsync.get_data_source(apiId=_MALFORMED_API_ID, name=ds_name))
    assert code2b == "BadRequestException", f"expected BadRequestException, got {code2b}"
    assert code2b_msg == f"Invalid API ID {_MALFORMED_API_ID}", f"unexpected message: {code2b_msg!r}"

    # The delete this check already performs at teardown is otherwise unasserted:
    # prove the SAME identifier is gone and unusable, not merely one never created.
    appsync.delete_data_source(apiId=api_id, name=ds_name)
    code3, code3_msg = _error(lambda: appsync.get_data_source(apiId=api_id, name=ds_name))
    assert code3 == "NotFoundException", f"expected NotFoundException after delete, got {code3}"
    assert code3_msg == f"Data source {ds_name} not found", f"unexpected message: {code3_msg!r}"
    code4, code4_msg = _error(lambda: appsync.update_data_source(apiId=api_id, name=ds_name, type="NONE"))
    assert code4 == "NotFoundException", f"expected NotFoundException on update-after-delete, got {code4}"
    assert code4_msg == f"Data source {ds_name} not found", f"unexpected message: {code4_msg!r}"


def _ident(ctx, prefix: str) -> str:
    return ctx.unique_name(f"sim2real_{prefix}_").replace("-", "_")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(name=name, authenticationType="API_KEY")
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises.
    An unexpected success raises: accepting what AWS refuses is a finding, not a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _delete_ds_if_present(appsync, api_id: str, name: str) -> None:
    try:
        appsync.delete_data_source(apiId=api_id, name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
