"""untag-open-idconnect-provider."""
from __future__ import annotations

import hashlib
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-open-idconnect-provider"
GROUP = 'tags'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the botocore (Code, Message) of the ClientError it raises. An unexpected
    SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected NoSuchEntity, but the call SUCCEEDED and returned {result!r}")


def _random_thumbprint():
    """A syntactically valid (40 hex char) SHA1-shaped thumbprint. IAM stores OIDC thumbprints
    verbatim when provided; it does not dial the URL to verify them against a live TLS cert."""
    return hashlib.sha1(uuid.uuid4().bytes).hexdigest()


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagOpenIDConnectProvider removes ONLY the named keys -- a second, untouched tag survives
    the call; untagging a nonexistent provider ARN is rejected NoSuchEntity."""
    iam = ctx.client("iam")
    host = f"{ctx.unique_name('oidcuntag')}.example.com"
    url = f"https://{host}/oidc"
    thumb = _random_thumbprint()
    created = iam.create_open_id_connect_provider(Url=url, ThumbprintList=[thumb])
    arn = created["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))
    iam.tag_open_id_connect_provider(
        OpenIDConnectProviderArn=arn,
        Tags=[{"Key": "sim2real-keep", "Value": "v1"}, {"Key": "sim2real-drop", "Value": "v2"}],
    )

    iam.untag_open_id_connect_provider(OpenIDConnectProviderArn=arn, TagKeys=["sim2real-drop"])
    tags = iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=arn)["Tags"]
    assert {"Key": "sim2real-keep", "Value": "v1"} in tags, f"untouched tag lost: {tags}"
    assert not any(t["Key"] == "sim2real-drop" for t in tags), f"targeted tag survived: {tags}"

    iam.untag_open_id_connect_provider(OpenIDConnectProviderArn=arn, TagKeys=["sim2real-keep"])
    tags_after = iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=arn)["Tags"]
    assert tags_after == [], f"expected no tags remaining, got {tags_after}"

    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = f"arn:aws:iam::{account}:oidc-provider/{ctx.unique_name('missing-')}.example.com"
    code, message = _error(
        lambda: iam.untag_open_id_connect_provider(
            OpenIDConnectProviderArn=fake_arn, TagKeys=["k"]
        )
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent provider ARN, got {code}"
    expected = f"OpenId connect Provider {fake_arn} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
