"""list-connection-functions-reflects-created-function."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-connection-functions-reflects-created-function"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_CODE = (
    b"function connectionHandler(connection) {\n"
    b"  connection.allow();\n"
    b"}\n"
)


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _list_all_connection_function_ids(cf) -> set[str]:
    ids: set[str] = set()
    marker = None
    while True:
        kwargs = {"MaxItems": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_connection_functions(**kwargs)
        for item in resp.get("ConnectionFunctions", []):
            ids.add(item["Id"])
        marker = resp.get("NextMarker")
        if not marker:
            break
    return ids


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created connection function shows up in ListConnectionFunctions and disappears once
    deleted; the dead Id is then unusable for both a read (EntityNotFound) and a repeat delete."""
    cf = ctx.client("cloudfront")

    name = ctx.unique_name("sim2real-cf-connfn-")
    created = cf.create_connection_function(
        Name=name,
        ConnectionFunctionCode=_CODE,
        ConnectionFunctionConfig={
            "Comment": "sim2real behavioral check connection function",
            "Runtime": "cloudfront-js-2.0",
        },
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
    )
    # The payload is nested under the root-tag key (ConnectionFunctionSummary);
    # ETag is a separate top-level field bound from the response header.
    summary = created["ConnectionFunctionSummary"]
    fn_id = summary["Id"]
    fn_etag = created["ETag"]

    deleted = {"done": False}

    def _cleanup():
        if deleted["done"]:
            return
        try:
            etag = cf.describe_connection_function(Identifier=fn_id, Stage="DEVELOPMENT")["ETag"]
            cf.delete_connection_function(Id=fn_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    assert summary["Name"] == name, f"expected Name={name!r}, got {summary['Name']!r}"
    assert summary["ConnectionFunctionConfig"]["Runtime"] == "cloudfront-js-2.0", (
        f"expected Runtime=cloudfront-js-2.0, got {summary['ConnectionFunctionConfig'].get('Runtime')!r}"
    )

    ids_after_create = _poll_until(
        lambda: _list_all_connection_function_ids(cf),
        lambda ids: fn_id in ids,
        timeout_s=30.0,
    )
    assert fn_id in ids_after_create, f"{fn_id} never appeared in ListConnectionFunctions"

    cf.delete_connection_function(Id=fn_id, IfMatch=fn_etag)
    deleted["done"] = True

    ids_after_delete = _poll_until(
        lambda: _list_all_connection_function_ids(cf),
        lambda ids: fn_id not in ids,
        timeout_s=30.0,
    )
    assert fn_id not in ids_after_delete, f"{fn_id} still listed in ListConnectionFunctions after delete"

    try:
        cf.describe_connection_function(Identifier=fn_id, Stage="DEVELOPMENT")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "EntityNotFound", f"expected EntityNotFound after delete, got {code}"
        message = exc.response["Error"].get("Message")
        assert message == "The specified connection function does not exist.", f"unexpected message {message!r}"
    else:
        raise AssertionError(f"DescribeConnectionFunction unexpectedly succeeded for deleted {fn_id}")

    try:
        cf.delete_connection_function(Id=fn_id, IfMatch=fn_etag)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "EntityNotFound", f"expected EntityNotFound on repeat delete, got {code}"
        message = exc.response["Error"].get("Message")
        assert message == "The specified connection function does not exist.", f"unexpected message {message!r}"
    else:
        raise AssertionError(f"repeat DeleteConnectionFunction unexpectedly succeeded for {fn_id}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
