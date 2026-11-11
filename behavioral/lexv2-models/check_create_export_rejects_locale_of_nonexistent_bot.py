"""create-export-rejects-locale-of-nonexistent-bot."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-export-rejects-locale-of-nonexistent-bot"
GROUP = 'export-content'
SERVICES = ['lexv2-models']

_LOCALE = "en_US"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises.

    Raises on an unexpected success rather than returning a falsy sentinel.
    """
    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error["Message"]
    raise AssertionError("the call was expected to fail but returned successfully")


def _missing_bot_id() -> str:
    """A syntactically valid Lex botId (10 alphanumerics) nothing created."""
    return secrets.token_hex(5).upper()


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateExport of a locale on a nonexistent bot is rejected, and the rejection leaves no
    export resource behind: ListExports scoped to that bot id stays empty.

    Reference: https://docs.aws.amazon.com/lexv2/latest/dg/export.html
    """
    lex = ctx.client("lexv2-models")
    missing_bot_id = _missing_bot_id()

    code, message = _error(lambda: lex.create_export(
        resourceSpecification={
            "botLocaleExportSpecification": {
                "botId": missing_bot_id, "botVersion": "DRAFT", "localeId": _LOCALE,
            }
        },
        fileFormat="LexJson",
    ))
    assert code == "PreconditionFailedException", (
        f"CreateExport against a nonexistent bot answered {code!r}, expected "
        "'PreconditionFailedException'"
    )
    assert message == (
        f"Bot with id {missing_bot_id} and version DRAFT in the request path does not exist."
    ), f"got message={message!r}"

    exports, token = [], None
    while True:
        page = lex.list_exports(
            botId=missing_bot_id, botVersion="DRAFT", localeId=_LOCALE,
            maxResults=100, **({"nextToken": token} if token else {}),
        )
        exports += page.get("exportSummaries", [])
        token = page.get("nextToken")
        if not token:
            break
    assert exports == [], (
        f"a rejected CreateExport against {missing_bot_id!r} still left export(s): {exports!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
