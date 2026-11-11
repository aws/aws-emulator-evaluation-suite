"""create-configuration-set-invalid-name-validated-before-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-configuration-set-invalid-name-validated-before-denied"
GROUP = "error-semantics"
SERVICES = ["pinpoint-sms-voice"]


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSet with a name containing spaces and punctuation gets BadRequestException
    with its exact message, while a valid name gets AccessDeniedException "Access Denied";
    ListConfigurationSets shows neither name."""
    client = ctx.client("pinpoint-sms-voice")
    invalid_name = "sim2real behav cfgset !!"

    code, message = _error_code(lambda: client.create_configuration_set(ConfigurationSetName=invalid_name))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = "The following parameter is null, empty or invalid: ['configurationSetName']"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # contrast: the identical call with a syntactically valid name is denied
    # differently -- by authorization, not validation -- confirming the ordering.
    valid_name = ctx.unique_name("sim2real-behav-cfgset-")
    valid_code, valid_message = _error_code(lambda: client.create_configuration_set(ConfigurationSetName=valid_name))
    assert valid_code == "AccessDeniedException", f"expected AccessDeniedException, got {valid_code!r}"
    assert valid_message == "Access Denied", f"expected the message 'Access Denied', got {valid_message!r}"

    # effect absent at the destination: neither call created anything, so neither
    # name may ever surface in an independent read.
    names: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = client.list_configuration_sets(**kwargs)
        names.extend(page.get("ConfigurationSets", []))
        token = page.get("NextToken")
        if not token:
            break
    assert invalid_name not in names, f"{invalid_name} must not appear after a validation rejection"
    assert valid_name not in names, f"{valid_name} must not appear after a denied create"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
