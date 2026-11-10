"""The offline demo replays the committed fixtures through the real aggregator.

The demo is a developer convenience, not a second detection path: it must use the
same parser, aggregator, and 20-sample gate as production, seed the inventory, and
refuse to write outside a throwaway directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.demo.behaviour_demo import run_demo

FIXTURES = Path(__file__).parents[1] / "tests" / "fixtures" / "behaviour"


def test_demo_replays_normal_then_attack_and_returns_behaviour_events(
    tmp_path: Path,
) -> None:
    events = run_demo(FIXTURES, tmp_path / "demo")

    assert any(event.detector == "behaviour.volume_spike" for event in events)
    assert any(event.detector == "behaviour.beaconing" for event in events)
    assert (tmp_path / "demo" / "gilgamesh.db").exists()


def test_demo_refuses_a_data_dir_outside_tmp_or_the_workspace() -> None:
    with pytest.raises(ValueError, match="refusing to write"):
        run_demo(FIXTURES, Path("/var/lib/gilgamesh-demo"))
