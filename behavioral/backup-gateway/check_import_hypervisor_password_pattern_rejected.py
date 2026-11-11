"""import-hypervisor-password-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-hypervisor-password-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["backup-gateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportHypervisorConfiguration rejects a Password containing a control character with
    ValidationException and creates no hypervisor; the same call with a valid Password succeeds."""
    bg = ctx.client("backup-gateway")
    name = ctx.unique_name("sim2real-bgw-badpw-")
    host = f"{ctx.unique_name('sim2real-bgw-badpw-host-')}.example.com"

    got = _client_error(lambda: bg.import_hypervisor_configuration(
        Name=name, Host=host, Username="sim2real-user", Password="bad\tpassword",
    ))
    expected_message = (
        "1 validation error detected: Value at 'password' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [ -~]+"
    )
    assert got == ("ValidationException", expected_message), (
        f"expected ValidationException {expected_message!r}, got {got!r}"
    )
    names = _all_hypervisor_names(bg)
    assert name not in names, f"expected {name!r} absent after rejection, found in {names!r}"

    # Positive control: the identical Name/Host with a well-formed Password succeeds.
    arn = _create_hypervisor(ctx, host=host, name=name)
    got = bg.get_hypervisor(HypervisorArn=arn)["Hypervisor"]
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Host"] == host, f"expected Host {host!r}, got {got['Host']!r}"


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
    arn = bg.import_hypervisor_configuration(
        Name=name or ctx.unique_name("sim2real-bgw-"),
        Host=host or f"{ctx.unique_name('sim2real-bgw-host-')}.example.com",
        Username="sim2real-user",
        Password="Sim2Real-Passw0rd!",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["HypervisorArn"]

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

