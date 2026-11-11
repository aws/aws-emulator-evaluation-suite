"""list-resources-invalid-type-rejected."""
from __future__ import annotations

import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resources-invalid-type-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListResources of a well-formed but unregistered TypeName is refused with TypeNotFoundException,
    HTTP 400 and "The type '<name>' cannot be found.", with no ResourceDescriptions, while the same
    call for AWS::SNS::Topic returns HTTP 200 and a ResourceDescriptions list."""
    cc = ctx.client("cloudcontrol")

    # Syntactically valid per the TypeName pattern ([A-Za-z0-9]{2,64}::...x3) but
    # not a real/registered CloudFormation extension in any account.
    suffix = uuid.uuid4().hex
    bogus_type_name = f"Sim2RealFake{suffix}::NoSuchService{suffix}::NoSuchResource{suffix}"

    code, http_status, err = _list_resources_error(cc, bogus_type_name)
    assert err is not None, "expected ListResources against a bogus TypeName to raise"
    assert code == "TypeNotFoundException", (
        f"expected TypeNotFoundException for unsupported TypeName, got {code!r}"
    )
    assert http_status == 400, f"expected HTTP 400 for TypeNotFoundException, got {http_status}"
    expected_message = f"The type '{bogus_type_name}' cannot be found."
    message = err.response.get("Error", {}).get("Message")
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"
    # A raised ClientError carries no ResourceDescriptions payload at all -- there is
    # no partial/successful result smuggled through the error response.
    assert "ResourceDescriptions" not in err.response, (
        "expected no ResourceDescriptions in an error response"
    )

    # Positive control: identical call shape, but a real, registered resource type.
    resp = cc.list_resources(TypeName="AWS::SNS::Topic")
    assert resp["TypeName"] == "AWS::SNS::Topic", (
        f"expected positive control to echo TypeName AWS::SNS::Topic, got {resp['TypeName']!r}"
    )
    assert isinstance(resp["ResourceDescriptions"], list), (
        f"expected ResourceDescriptions to be a list, got {type(resp['ResourceDescriptions'])!r}"
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected HTTP 200 for the positive control, got "
        f"{resp['ResponseMetadata']['HTTPStatusCode']}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str | None, int | None, ClientError | None]:
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return code, status, exc
    raise AssertionError("expected ListResources against a bogus TypeName to raise, but it succeeded")


def _list_resources_error(cc, type_name: str) -> tuple[str | None, int | None, ClientError | None]:
    return _error_code(lambda: cc.list_resources(TypeName=type_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
