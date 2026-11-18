"""Tehlikeli komut tespiti ve risk seviyesi.

Iki katman var:
  - TABAN (hardline): geri alinamaz yikim. Her seferinde sorulur, kalici izin
    verilemez, auto mod bunu asla gecemez.
  - TEHLIKELI (dangerous): riskli ama geri alinabilir/kabul edilebilir.
    Kullanici onaylayabilir, bu sohbet icin kalici izin verebilir.

Desen listeleri Hermes Agent'tan (MIT) uyarlandi; bu sarmalayici bu projeye ait.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_guard.hardline import is_hardline
from agent_guard.patterns import DANGEROUS_PATTERNS_COMPILED

# Ayristirilamayacak kadar uzun komutlar guvenli tarafa dusurulur.
MAX_COMMAND_LENGTH = 8000


@dataclass(frozen=True)
class Finding:
    """Tek bir tespit sonucu."""

    dangerous: bool
    description: str | None = None
    hardline: bool = False

    def __bool__(self) -> bool:
        return self.dangerous


SAFE = Finding(False)


def detect(command: str) -> Finding:
    """Komutu tara ve risk seviyesini dondur.

    Guvenli tarafa dusme ilkesi: emin olunamayan durumlarda tehlikeli sayilir.
    Yanlis pozitif kullaniciyi bir kez rahatsiz eder; yanlis negatif veri
    kaybettirir.
    """
    if not command or not command.strip():
        return SAFE

    if len(command) > MAX_COMMAND_LENGTH:
        return Finding(True, "komut ayristirma sinirini asti (guvenlik icin engellendi)", hardline=True)

    # Taban once denetlenir: bir komut hem tabana hem tehlikeli listeye
    # girebilir, bu durumda taban kazanmalidir.
    floor = is_hardline(command)
    if floor:
        return Finding(True, floor, hardline=True)

    lowered = command.lower()
    for pattern, description in DANGEROUS_PATTERNS_COMPILED:
        if pattern.search(lowered):
            return Finding(True, description, hardline=False)

    return SAFE
