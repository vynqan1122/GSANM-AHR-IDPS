from __future__ import annotations

from dataset_collection.traffic import BENIGN_FLOW


def main() -> None:
    for request in BENIGN_FLOW:
        print(f"{request.method} {request.path}")


if __name__ == "__main__":
    main()
