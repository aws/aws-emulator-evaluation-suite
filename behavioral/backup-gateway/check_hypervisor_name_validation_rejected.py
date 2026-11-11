"""hypervisor-name-validation-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "hypervisor-name-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["backup-gateway"]

NAME_PATTERN = "[a-zA-Z0-9-]*"


def _name_message(value: str, constraint: str) -> str:
    return (
        f"1 validation error detected: Value '{value}' at 'name' failed to satisfy constraint: "
        f"{constraint}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportHypervisorConfiguration and UpdateHypervisor reject a Name with invalid characters or
    over 100 characters with ValidationException; the Name is unchanged and a valid rename
    succeeds."""
    bg = ctx.client("backup-gateway")

    # 1) Create-time: invalid characters are rejected, nothing is created.
    bad_name = "bad name!!"
    bad_char = code, message = _client_error(lambda: bg.import_hypervisor_configuration(
        Name=bad_name,
        Host=f"{ctx.unique_name('sim2real-bgw-h1-')}.example.com",
        Username="sim2real-user",
        Password="Sim2Real-Passw0rd!",
    ))
    pattern_constraint = f"Member must satisfy regular expression pattern: {NAME_PATTERN}"
    assert code == "ValidationException", (
        f"expected ValidationException for a Name with invalid characters, got {bad_char!r}"
    )
    assert message == _name_message(bad_name, pattern_constraint), (
        f"expected the pattern-constraint message for a Name with invalid characters, got {bad_char!r}"
    )
    assert bad_name not in _all_hypervisor_names(bg), (
        f"expected no Hypervisor named {bad_name!r} after a rejected import, but it is listed"
    )

    # 2) Create-time: a name over the 100-character limit is rejected, nothing is created.
    too_long_name = "a" * 101
    too_long = code, message = _client_error(lambda: bg.import_hypervisor_configuration(
        Name=too_long_name,
        Host=f"{ctx.unique_name('sim2real-bgw-h2-')}.example.com",
        Username="sim2real-user",
        Password="Sim2Real-Passw0rd!",
    ))
    length_constraint = "Member must have length less than or equal to 100"
    assert code == "ValidationException", (
        f"expected ValidationException for a 101-character Name, got {too_long!r}"
    )
    assert message == _name_message(too_long_name, length_constraint), (
        f"expected the length-constraint message for a 101-character Name, got {too_long!r}"
    )
    assert too_long_name not in _all_hypervisor_names(bg), (
        f"expected no Hypervisor named {too_long_name!r} after a rejected import, but it is listed"
    )

    # 3) Update-time: an invalid-character rename is rejected and the old Name is preserved.
    original_name = ctx.unique_name("sim2real-bgw-")
    arn = _create_hypervisor(ctx, name=original_name)

    rename = code, message = _client_error(lambda: bg.update_hypervisor(HypervisorArn=arn, Name=bad_name))
    assert code == "ValidationException", (
        f"expected ValidationException for an UpdateHypervisor rename to {bad_name!r}, "
        f"got {rename!r}"
    )
    assert message == _name_message(bad_name, pattern_constraint), (
        f"expected the pattern-constraint message for an UpdateHypervisor rename to {bad_name!r}, "
        f"got {rename!r}"
    )
    current_name = bg.get_hypervisor(HypervisorArn=arn)["Hypervisor"]["Name"]
    assert current_name == original_name, (
        f"expected the rejected rename to leave Name as {original_name!r}, got {current_name!r}"
    )

    # 4) Positive control: a well-formed rename succeeds.
    new_name = ctx.unique_name("sim2real-bgw-renamed-")
    bg.update_hypervisor(HypervisorArn=arn, Name=new_name)
    renamed = bg.get_hypervisor(HypervisorArn=arn)["Hypervisor"]["Name"]
    assert renamed == new_name, (
        f"expected UpdateHypervisor to rename to {new_name!r}, got {renamed!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _all_hypervisor_names(bg) -> set[str]:
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = bg.list_hypervisors(**kwargs)
        names.update(h["Name"] for h in resp.get("Hypervisors", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _create_hypervisor(ctx, host=None, name=None):
    bg = ctx.client("backup-gateway")
    kwargs = {
        "Name": name or ctx.unique_name("sim2real-bgw-"),
        "Host": host or f"{ctx.unique_name('sim2real-bgw-host-')}.example.com",
        "Username": "sim2real-user",
        "Password": "Sim2Real-Passw0rd!",
        "Tags": [{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    }
    arn = bg.import_hypervisor_configuration(**kwargs)["HypervisorArn"]

    def _cleanup():
        try:
            bg.delete_hypervisor(HypervisorArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
