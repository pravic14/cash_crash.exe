"""Red Team points. A bounty counts only after money actually moves without a token."""

from __future__ import annotations

from dataclasses import dataclass

from shared.schemas import RiskBand, Verdict


@dataclass
class RedTeam:
    hold_points: int = 0
    evasion_points: int = 0
    bounties: int = 0

    def note(
        self,
        verdict: Verdict | None,
        band: RiskBand | None,
        trusted_override: bool,
        executed: bool,
        authorised: bool,
    ) -> None:
        if verdict == Verdict.HOLD:
            self.hold_points += 1
        if band == RiskBand.HIGH and verdict == Verdict.ALLOW and not trusted_override:
            self.evasion_points += 1
        if executed and not authorised:
            self.bounties += 1

    def snapshot(self) -> dict:
        return {
            "hold_points": self.hold_points,
            "evasion_points": self.evasion_points,
            "bounties": self.bounties,
        }
