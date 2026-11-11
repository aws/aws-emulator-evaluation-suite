def handler(event, context):
    """Echoes the marker the check sent, so Invoke proves the real asset's code is running."""
    return {"echo": event["marker"]}
