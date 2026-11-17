"""create-data-catalog-name-space-and-unicode-accepted-control-char-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-data-catalog-name-space-and-unicode-accepted-control-char-rejected"
GROUP = "representation"
SERVICES = ["athena"]


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _names(athena) -> set:
    return {
        s["CatalogName"]
        for page in athena.get_paginator("list_data_catalogs").paginate()
        for s in page["DataCatalogsSummary"]
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataCatalog accepts a Name built only from letters, digits, underscore, at-sign
    and hyphen, but refuses one holding a space (InvalidRequestException naming the value) and
    one holding a control character below U+0020 (InvalidRequestException naming the pattern)."""
    athena = ctx.client("athena")
    account_id = ctx.account

    doc_name = ctx.unique_name("sim2real_cat@") + "-ok"
    athena.create_data_catalog(
        Name=doc_name, Type="GLUE", Description="doc-charset",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=doc_name))

    fetched = athena.get_data_catalog(Name=doc_name)["DataCatalog"]
    assert fetched["Name"] == doc_name, (
        f"expected GetDataCatalog to echo Name {doc_name!r} exactly, got {fetched['Name']!r}"
    )
    assert doc_name in _names(athena), f"expected {doc_name!r} in ListDataCatalogs after creation"

    space_name = ctx.unique_name("sim2real cat ") + " café"
    code, message = _error(
        lambda: athena.create_data_catalog(
            Name=space_name, Type="GLUE", Description="space-unicode",
            Parameters={"catalog-id": account_id},
        )
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for a Name holding a space and non-ASCII letters, got {code!r}"
    )
    assert message == f"DataCatalog name {space_name} is invalid.", (
        f"unexpected CreateDataCatalog message for a space-and-unicode Name: {message!r}"
    )
    assert space_name not in _names(athena), (
        f"the refused space-and-unicode name {space_name!r} must never appear in ListDataCatalogs"
    )

    control_char_name = ctx.unique_name("sim2real-cat-ctrl-") + "\x01"
    code2, message2 = _error(
        lambda: athena.create_data_catalog(
            Name=control_char_name, Type="GLUE", Description="control-char-name",
            Parameters={"catalog-id": account_id},
        )
    )
    assert code2 == "InvalidRequestException", (
        f"expected InvalidRequestException for a Name holding U+0001, got {code2!r}"
    )
    assert message2 == (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        "[\\u0020-\\uD7FF\\uE000-\\uFFFD\\uD800\\uDC00-\\uDBFF\\uDFFF\\t]*"
    ), f"unexpected CreateDataCatalog message for a control-character Name: {message2!r}"
    assert control_char_name not in _names(athena), (
        "the refused control-character name must never appear in ListDataCatalogs"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
