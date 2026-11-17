"""put-data-protection-policy-malformed-document-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-data-protection-policy-malformed-document-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDataProtectionPolicy with a policyDocument that is not valid JSON is rejected with
    InvalidParameterException naming the parse failure, and the log group keeps no policy."""
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-pdpneg-lg-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    valid_doc = json.dumps(
        {
            "Name": "sim2real-pdpneg-policy",
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "auditStatement",
                    "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                    "Operation": {"Audit": {"FindingsDestination": {}}},
                },
                {
                    "Sid": "deidentifyStatement",
                    "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                    "Operation": {"Deidentify": {"MaskConfig": {}}},
                },
            ],
        }
    )

    # Positive control: a well-formed policy document is accepted and round-trips.
    logs.put_data_protection_policy(logGroupIdentifier=group, policyDocument=valid_doc)
    got = json.loads(logs.get_data_protection_policy(logGroupIdentifier=group)["policyDocument"])
    assert got == json.loads(valid_doc), f"expected the valid policy to round-trip, got {got!r}"

    # Negative: a string that is not valid JSON at all.
    malformed_doc = '{"Name": not valid json here}'
    code, message = _error(
        lambda: logs.put_data_protection_policy(logGroupIdentifier=group, policyDocument=malformed_doc)
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a malformed policyDocument, got {code!r} {message!r}"
    )
    expected_message = (
        "Invalid policy JSON: Unrecognized token 'not': was expecting (JSON String, Number, "
        "Array, Object or token 'null', 'true' or 'false')\n"
        " at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); "
        "line: 1, column: 10]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the rejected call did not change the policy already in place.
    still_there = json.loads(logs.get_data_protection_policy(logGroupIdentifier=group)["policyDocument"])
    assert still_there == json.loads(valid_doc), (
        f"expected the rejected PutDataProtectionPolicy to leave the existing policy "
        f"untouched, got {still_there!r}"
    )


def _error(fn: Callable[[], Any]):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
