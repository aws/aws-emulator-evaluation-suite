"""delete-encoder-configuration-removes-from-list."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-encoder-configuration-removes-from-list"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting an EncoderConfiguration doesn't just return 200: the resource actually
    disappears from ListEncoderConfigurations, GetEncoderConfiguration starts reporting
    ResourceNotFoundException, and a mutation against the now-dead ARN is rejected too."""
    client = ctx.client("ivs-realtime")
    arn = client.create_encoder_configuration(
        name=ctx.unique_name("sim2real-encoder"), tags={"sim2real": "true"}
    )["encoderConfiguration"]["arn"]
    ctx.on_cleanup(lambda: _delete_if_present(client, arn))

    assert arn in _list_arns(client)

    client.delete_encoder_configuration(arn=arn)

    assert arn not in _list_arns(client)
    got = _client_error(lambda: client.get_encoder_configuration(arn=arn))
    assert got.get("Code") == "ResourceNotFoundException", got
    assert got.get("Message") == f"Resource: {arn} not found", got

    tagged = _client_error(lambda: client.tag_resource(resourceArn=arn, tags={"k": "v"}))
    assert tagged.get("Code") == "NotFoundException", tagged
    assert tagged.get("Message") == "Resource was not found", tagged


def _list_arns(client) -> set[str]:
    arns: set[str] = set()
    next_token = None
    while True:
        params = {"nextToken": next_token} if next_token else {}
        resp = client.list_encoder_configurations(**params)
        arns.update(e["arn"] for e in resp["encoderConfigurations"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



def _delete_if_present(client, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        client.delete_encoder_configuration(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
