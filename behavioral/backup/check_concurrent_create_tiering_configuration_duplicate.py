"""concurrent-create-tiering-configuration-duplicate."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-tiering-configuration-duplicate"
GROUP = "concurrency"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateTieringConfiguration calls with one name produce exactly one configuration and
    conflict rejections for the rest; after deleting it, a read returns
    ResourceNotFoundException."""
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real_tier_").replace("-", "_")

    def create_body():
        return {
            "TieringConfigurationName": name,
            "BackupVaultName": "*",
            "ResourceSelection": [
                {
                    "Resources": ["*"],
                    "TieringDownSettingsInDays": 90,
                    "ResourceType": "S3",
                }
            ],
        }

    workers = 6
    barrier = threading.Barrier(workers)

    def attempt(_i: int):
        barrier.wait()
        try:
            backup.create_tiering_configuration(
                TieringConfiguration=create_body(),
                TieringConfigurationTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real_tier"},
            )
            return ("ok", None, None)
        except Exception as e:  # noqa: BLE001
            return ("err", _error_code_of(e), _error_message_of(e))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(attempt, range(workers)))

    ctx.on_cleanup(lambda: _safe(lambda: backup.delete_tiering_configuration(TieringConfigurationName=name)))

    successes = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "err"]

    assert len(successes) == 1, f"expected exactly one winning create, got {len(successes)}"
    for _, code, message in errors:
        assert code == "AlreadyExistsException", f"unexpected duplicate-create error code: {code}"
        assert message == "Tiering configuration with the same name already exists", (
            f"unexpected duplicate-create message: {message!r}"
        )

    got = backup.get_tiering_configuration(TieringConfigurationName=name)
    assert got["TieringConfiguration"]["TieringConfigurationName"] == name, (
        f"expected the surviving configuration to be named {name!r}, "
        f"got {got['TieringConfiguration'].get('TieringConfigurationName')!r}"
    )

    backup.delete_tiering_configuration(TieringConfigurationName=name)
    not_found_code, not_found_message = _err(
        lambda: backup.get_tiering_configuration(TieringConfigurationName=name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected the deleted tiering configuration to be gone (ResourceNotFoundException), "
        f"got {not_found_code}"
    )
    assert not_found_message == "Cannot find tiering configuration", (
        f"unexpected not-found message: {not_found_message!r}"
    )


def _error_code_of(exc: Exception) -> str | None:
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return None


def _error_message_of(exc: Exception) -> str | None:
    if isinstance(exc, ClientError):
        return exc.response["Error"].get("Message")
    return None


def _err(fn) -> tuple[str | None, str | None]:
    """Call fn(); return the botocore (Error.Code, Error.Message). A success raises."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return _error_code_of(e), _error_message_of(e)
    raise AssertionError("expected the call to be refused, but it succeeded")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
