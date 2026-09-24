from __future__ import annotations

import json

import websocket


def main() -> None:
    results = {}
    for name in ("system", "events", "alerts", "incidents"):
        connection = websocket.create_connection(
            f"ws://127.0.0.1:8080/ws/{name}", timeout=5
        )
        try:
            message = connection.recv()
            if not message:
                raise RuntimeError(f"/ws/{name} returned an empty message")
            results[name] = {"status": "PASS", "bytes": len(message)}
        finally:
            connection.close()
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    main()
