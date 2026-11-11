"""describe-endpoint-types."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-endpoint-types"
GROUP = 'endpoint'
SERVICES = ['iot']


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEndpoint returns a distinct, well-formed host per supported endpoint type,
    and the retired iot:Jobs endpoint type is now actively rejected."""
    iot = ctx.client("iot")
    data_ats = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    creds = iot.describe_endpoint(endpointType="iot:CredentialProvider")["endpointAddress"]

    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", data_ats), data_ats
    assert ".iot." in data_ats, data_ats
    assert "credentials" in creds, creds
    assert data_ats != creds, "endpoint types must differ"

    # iot:Jobs was folded into iot:Data-ATS and is now rejected outright.
    code_jobs, message_jobs = _error_code(lambda: iot.describe_endpoint(endpointType="iot:Jobs"))
    assert code_jobs == "InvalidRequestException", (
        f"retired iot:Jobs endpointType must be rejected, got {code_jobs}"
    )
    expected_jobs = (
        "IoT Jobs and Commands APIs are now available through iot:Data-ATS endpoints instead of "
        "iot:Jobs endpoints. Please use iot:Data-ATS."
    )
    assert message_jobs == expected_jobs, f"expected message {expected_jobs!r}, got {message_jobs!r}"

    code, message = _error_code(lambda: iot.describe_endpoint(endpointType="iot:NotAnEndpointType"))
    assert code == "InvalidRequestException", (
        f"an unknown endpointType must be rejected, got {code}"
    )
    expected_unknown = "Endpoint type iot:NotAnEndpointType not recognized."
    assert message == expected_unknown, f"expected message {expected_unknown!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
