"""security-configuration-malformed-json-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "security-configuration-malformed-json-rejected"
GROUP = "representation"
SERVICES = ["emr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSecurityConfiguration rejects malformed JSON; a valid document still succeeds."""
    emr = ctx.client("emr")

    bad_name = ctx.unique_name("sim2real-emr-secconf-bad-")
    good_name = ctx.unique_name("sim2real-emr-secconf-good-")

    code, message = _error(
        lambda: emr.create_security_configuration(
            Name=bad_name, SecurityConfiguration="{not valid json"
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected = "Invalid security configuration; Malformed Json string."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the malformed configuration was never persisted
    not_found_code, not_found_message = _error(
        lambda: emr.describe_security_configuration(Name=bad_name)
    )
    assert not_found_code == "InvalidRequestException", (
        f"expected the never-created {bad_name!r} to describe as InvalidRequestException, "
        f"got {not_found_code!r}"
    )
    expected = f'Security configuration with name "{bad_name}" does not exist.'
    assert not_found_message == expected, (
        f"expected message {expected!r}, got {not_found_message!r}"
    )

    # positive control: a well-formed document is accepted, persisted, and readable back
    valid_doc = {
        "EncryptionConfiguration": {
            "EnableInTransitEncryption": False,
            "EnableAtRestEncryption": False,
        }
    }
    emr.create_security_configuration(Name=good_name, SecurityConfiguration=json.dumps(valid_doc))
    ctx.on_cleanup(lambda: emr.delete_security_configuration(Name=good_name))

    described = emr.describe_security_configuration(Name=good_name)
    assert described["Name"] == good_name, f"expected Name={good_name!r}, got {described['Name']!r}"
    assert json.loads(described["SecurityConfiguration"]) == valid_doc, (
        f"expected the roundtripped document to equal {valid_doc!r}, "
        f"got {described['SecurityConfiguration']!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
