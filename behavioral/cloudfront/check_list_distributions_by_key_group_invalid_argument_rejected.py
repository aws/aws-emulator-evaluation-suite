"""list-distributions-by-key-group-invalid-argument-rejected."""
from __future__ import annotations

import subprocess
import tempfile
import uuid
from pathlib import Path

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "list-distributions-by-key-group-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByKeyGroup on a well-formed but nonexistent KeyGroupId is refused with
    NoSuchResource and the exact message, while on a real unused key group it returns 0 distributions
    before and after the refused call."""
    cf = ctx.client("cloudfront")
    public_key_id, public_key_etag = _create_public_key(ctx)
    key_group_id = _create_key_group(ctx, public_key_id)

    # positive control: a real, well-formed key group id that no distribution references.
    ok = cf.list_distributions_by_key_group(KeyGroupId=key_group_id)
    assert ok["DistributionIdList"]["Quantity"] == 0, (
        f"expected the freshly created key group {key_group_id} to trust 0 distributions, "
        f"got {ok['DistributionIdList']['Quantity']}"
    )

    fake_id = str(uuid.uuid4())
    code, message = _error_code_and_message(lambda: cf.list_distributions_by_key_group(KeyGroupId=fake_id))
    assert code == "NoSuchResource", f"expected NoSuchResource, got {code!r}"
    assert message == "The specified key group does not exist.", f"unexpected message {message!r}"

    # the nonexistent lookup must not have fabricated any distribution associations for the
    # real key group either.
    still_empty = cf.list_distributions_by_key_group(KeyGroupId=key_group_id)
    assert still_empty["DistributionIdList"]["Quantity"] == 0, (
        f"listing a nonexistent key group must not affect the real key group {key_group_id}, "
        f"but it now reports {still_empty['DistributionIdList']['Quantity']} distributions"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListDistributionsByKeyGroup to reject a nonexistent KeyGroupId, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _generate_rsa_public_key_pem() -> str:
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "key.pem"
        pub_path = Path(d) / "pub.pem"
        require_tools("openssl")
        subprocess.run(
            ["openssl", "genrsa", "-out", str(key_path), "2048"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "rsa", "-in", str(key_path), "-pubout", "-out", str(pub_path)],
            check=True,
            capture_output=True,
        )
        return pub_path.read_text()


def _create_public_key(ctx):
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()
    resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-pk-"),
            "Name": ctx.unique_name("sim2real-cf-pk-"),
            "EncodedKey": pem,
            "Comment": "sim2real behavioral fixture",
        }
    )
    key_id = resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_public_key(ctx, key_id))
    return key_id, resp["ETag"]


def _delete_public_key(ctx, key_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_public_key(Id=key_id)
        cf.delete_public_key(Id=key_id, IfMatch=got["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicKey":
            raise


def _create_key_group(ctx, public_key_id: str) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_key_group(
        KeyGroupConfig={
            "Name": ctx.unique_name("sim2real-cf-kg-"),
            "Items": [public_key_id],
            "Comment": "sim2real behavioral fixture",
        }
    )
    kg_id = resp["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_key_group(ctx, kg_id))
    return kg_id


def _delete_key_group(ctx, kg_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_key_group(Id=kg_id)
        cf.delete_key_group(Id=kg_id, IfMatch=got["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResource":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
