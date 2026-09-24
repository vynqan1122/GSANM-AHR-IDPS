"""Command line interface for Phase 5 dataset collection."""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from pathlib import Path

from .db import connect_from_env, create_scenario, finish_scenario, label_scenario
from .exporter import export_dataset
from .guard import UnsafeTarget, assert_lab_target
from .traffic import BENIGN_FLOW, CONTROLLED_SCENARIOS, run_specs


def _scenario_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


async def run_benign(args: argparse.Namespace) -> None:
    target = assert_lab_target(args.target)
    scenario_id = args.scenario_id or _scenario_id("benign")
    connection = await connect_from_env()
    try:
        await create_scenario(
            connection,
            scenario_id=scenario_id,
            name=args.name,
            label="benign",
            attack_type=None,
            mode=args.mode,
            source="phase5-benign-generator",
            target=target,
            notes=args.notes,
        )
        count = await run_specs(target, BENIGN_FLOW, scenario_id=scenario_id, repeat=args.repeat, fast=args.fast)
        linked = await finish_scenario(connection, scenario_id=scenario_id, request_count=count)
        for _ in range(args.label_wait_seconds):
            if linked > 0:
                break
            await asyncio.sleep(1)
            linked = await label_scenario(connection, scenario_id=scenario_id)
    finally:
        await connection.close()
    print(json.dumps({"scenario_id": scenario_id, "requests": count, "linked_events": linked}, sort_keys=True))


async def run_controlled(args: argparse.Namespace) -> None:
    target = assert_lab_target(args.target)
    scenario_id = args.scenario_id or _scenario_id(args.attack_type)
    specs = CONTROLLED_SCENARIOS[args.attack_type]
    connection = await connect_from_env()
    try:
        await create_scenario(
            connection,
            scenario_id=scenario_id,
            name=args.name or f"controlled-{args.attack_type}",
            label="attack",
            attack_type=args.attack_type,
            mode=args.mode,
            source="phase5-controlled-runner",
            target=target,
            notes=args.notes,
        )
        count = await run_specs(target, specs, scenario_id=scenario_id, repeat=args.repeat, fast=args.fast)
        linked = await finish_scenario(connection, scenario_id=scenario_id, request_count=count)
        for _ in range(args.label_wait_seconds):
            if linked > 0:
                break
            await asyncio.sleep(1)
            linked = await label_scenario(connection, scenario_id=scenario_id)
    finally:
        await connection.close()
    print(json.dumps({"scenario_id": scenario_id, "requests": count, "linked_events": linked}, sort_keys=True))


async def label(args: argparse.Namespace) -> None:
    connection = await connect_from_env()
    try:
        linked = await label_scenario(connection, scenario_id=args.scenario_id)
    finally:
        await connection.close()
    print(json.dumps({"scenario_id": args.scenario_id, "linked_events": linked}, sort_keys=True))


async def export(args: argparse.Namespace) -> None:
    connection = await connect_from_env()
    try:
        manifest = await export_dataset(connection, Path(args.output))
    finally:
        await connection.close()
    print(json.dumps(manifest, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="AHR-IDPS Phase 5 dataset collection")
    root.add_argument("--target", default="http://nginx", help="lab URL only; external URLs abort")
    sub = root.add_subparsers(dest="command", required=True)

    benign = sub.add_parser("run-benign")
    benign.add_argument("--scenario-id")
    benign.add_argument("--name", default="benign-browser-flow")
    benign.add_argument("--mode", choices=["NORMAL_MODE", "COLLECTION_MODE", "RESEARCH_MODE"], default="COLLECTION_MODE")
    benign.add_argument("--repeat", type=int, default=2)
    benign.add_argument("--fast", action="store_true")
    benign.add_argument("--notes")
    benign.add_argument("--label-wait-seconds", type=int, default=60)
    benign.set_defaults(func=run_benign)

    controlled = sub.add_parser("run-controlled")
    controlled.add_argument("attack_type", choices=sorted(CONTROLLED_SCENARIOS))
    controlled.add_argument("--scenario-id")
    controlled.add_argument("--name")
    controlled.add_argument("--mode", choices=["COLLECTION_MODE", "RESEARCH_MODE"], default="COLLECTION_MODE")
    controlled.add_argument("--repeat", type=int, default=1)
    controlled.add_argument("--fast", action="store_true")
    controlled.add_argument("--notes")
    controlled.add_argument("--label-wait-seconds", type=int, default=60)
    controlled.set_defaults(func=run_controlled)

    relabel = sub.add_parser("label")
    relabel.add_argument("scenario_id")
    relabel.set_defaults(func=label)

    exporter = sub.add_parser("export")
    exporter.add_argument("--output", default="/opt/ahr-idps/datasets")
    exporter.set_defaults(func=export)

    return root


def main() -> None:
    args = parser().parse_args()
    try:
        asyncio.run(args.func(args))
    except UnsafeTarget as exc:
        raise SystemExit(f"ABORT: {exc}") from exc


if __name__ == "__main__":
    main()
