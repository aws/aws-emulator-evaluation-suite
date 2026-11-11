"""get-hypervisor-arn-validation-and-not-found."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-hypervisor-arn-validation-and-not-found"
GROUP = "overly-permissive"
SERVICES = ["backup-gateway"]

HYPERVISOR_NOT_FOUND = "The hypervisor is not found."
HYPERVISOR_ARN_PATTERN = r"arn:(aws|aws-cn|aws-us-gov):backup-gateway(:[a-zA-Z-0-9]+){3}\/[a-zA-Z-0-9]+"


def _arn_pattern_message(value: str) -> str:
    return (
        f"1 validation error detected: Value '{value}' at 'hypervisorArn' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: {HYPERVISOR_ARN_PATTERN}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetHypervisor distinguishes a malformed ARN (ValidationException) from a well-formed
    ARN that simply does not exist (ResourceNotFoundException), and still succeeds for a real,
    existing Hypervisor ARN."""
    bg = ctx.client("backup-gateway")

    # Long enough to pass botocore's client-side length check (min 50) but does not match the
    # ARN pattern, so the rejection is a real service-side ValidationException, not a local
    # ParamValidationError.
    malformed_arn = "not-an-arn-" + "x" * 45
    malformed = _client_error(lambda: bg.get_hypervisor(HypervisorArn=malformed_arn))
    assert malformed == ("ValidationException", _arn_pattern_message(malformed_arn)), (
        f"expected ValidationException for a malformed HypervisorArn, got {malformed!r}"
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = (
        f"arn:aws:backup-gateway:{ctx.region}:{account_id}:hypervisor/"
        f"{ctx.unique_name('sim2real-bgw-ghost-')}"
    )
    not_found = _client_error(lambda: bg.get_hypervisor(HypervisorArn=fake_arn))
    assert not_found == ("ResourceNotFoundException", HYPERVISOR_NOT_FOUND), (
        f"expected ResourceNotFoundException for a well-formed but nonexistent HypervisorArn, "
        f"got {not_found!r}"
    )

    # Positive control: a real, existing Hypervisor is fetched successfully.
    real_arn = _create_hypervisor(ctx)
    got = bg.get_hypervisor(HypervisorArn=real_arn)["Hypervisor"]
    assert got["HypervisorArn"] == real_arn, (
        f"expected GetHypervisor to return {real_arn!r}, got {got.get('HypervisorArn')!r}"
    )

    # Delete proves gone and unusable: an independent read now gets the specific not-found
    # code, and a mutation on the dead id fails the same way rather than silently no-op'ing.
    bg.delete_hypervisor(HypervisorArn=real_arn)

    post_delete_get = _client_error(lambda: bg.get_hypervisor(HypervisorArn=real_arn))
    assert post_delete_get == ("ResourceNotFoundException", HYPERVISOR_NOT_FOUND), (
        f"expected GetHypervisor on a deleted HypervisorArn to return ResourceNotFoundException, "
        f"got {post_delete_get!r}"
    )

    post_delete_update = _client_error(
        lambda: bg.update_hypervisor(HypervisorArn=real_arn, Name=ctx.unique_name("sim2real-bgw-dead-"))
    )
    assert post_delete_update == ("ResourceNotFoundException", HYPERVISOR_NOT_FOUND), (
        f"expected UpdateHypervisor on a deleted HypervisorArn to return ResourceNotFoundException, "
        f"got {post_delete_update!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
