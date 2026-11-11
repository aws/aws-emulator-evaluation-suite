"""import-hypervisor-with-kms-key-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-hypervisor-with-kms-key-round-trip"
GROUP = "cross-service"
SERVICES = ["backup-gateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A customer-managed KMS key supplied to ImportHypervisorConfiguration is stored on the
    Hypervisor and reported back verbatim via GetHypervisor. KMS key creation is cheap and
    fast, so unlike a native-protocol provisioning check this always runs."""
    kms = ctx.client("kms")
    key = kms.create_key(Description=ctx.unique_name("sim2real-bgw-key-"))["KeyMetadata"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))

    bg = ctx.client("backup-gateway")
    name = ctx.unique_name("sim2real-bgw-")
    host = f"{ctx.unique_name('sim2real-bgw-host-')}.example.com"
    arn = bg.import_hypervisor_configuration(
        Name=name,
        Host=host,
        Username="sim2real-user",
        Password="Sim2Real-Passw0rd!",
        KmsKeyArn=key_arn,
    )["HypervisorArn"]
    ctx.on_cleanup(lambda: _safe_delete(bg, arn))

    got = bg.get_hypervisor(HypervisorArn=arn)["Hypervisor"]
    assert got["KmsKeyArn"] == key_arn, f"expected KmsKeyArn {key_arn!r}, got {got.get('KmsKeyArn')!r}"


def _safe_delete(bg, arn: str) -> None:
    try:
        bg.delete_hypervisor(HypervisorArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
