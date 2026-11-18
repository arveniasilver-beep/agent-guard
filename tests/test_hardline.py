"""Taban katmani testleri.

Taban, auto modun asla gecemeyecegi zemindir. Buradaki testler bir regresyonun
tabani sessizce delmesini engellemek icin var.
"""

import pytest
from langgraph.types import Command

from agent_guard.card import OPTION_ONCE, OPTION_SESSION, SOURCE, request_id_for
from agent_guard.detect import detect
from agent_guard.hardline import is_hardline
from agent_guard.middleware import ApprovalGateMiddleware

from tests.test_middleware import Sayac, istek, karar  # noqa: F401

TABAN_KOMUTLARI = [
    "rm -rf /",
    'rm -rf "/"',
    "rm -rf $HOME",
    "rm -rf ${HOME}",
    "rm -rf /etc",
    "mkfs.ext4 /dev/sda1",
    "dd if=/dev/zero of=/dev/sda",
    ":(){ :|:& };:",
    "shutdown -h now",
    "systemctl poweroff",
    "init 0",
]

TABAN_DISI_TEHLIKELI = [
    "rm -rf build/",
    "git push --force origin main",
    "git reset --hard HEAD~3",
    "DROP TABLE users;",
]


@pytest.fixture(autouse=True)
def manuel_mod(monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_MODE", "manual")


@pytest.mark.parametrize("komut", TABAN_KOMUTLARI)
def test_geri_alinamaz_komutlar_tabana_girer(komut):
    assert is_hardline(komut), f"{komut!r} tabana girmeliydi"
    assert detect(komut).hardline


@pytest.mark.parametrize("komut", TABAN_DISI_TEHLIKELI)
def test_geri_alinabilir_riskler_tabana_girmez(komut):
    """Taban dar tutulmali; her riski tabana koymak kullanilamaz hale getirir."""
    assert not is_hardline(komut), f"{komut!r} taban degil, sadece tehlikeli olmali"
    bulgu = detect(komut)
    assert bulgu and not bulgu.hardline


def test_taban_kartinda_kalici_izin_secenegi_yok():
    mw = ApprovalGateMiddleware()
    sonuc = mw.wrap_tool_call(istek("bash", "rm -rf /"), Sayac())

    kart = sonuc.update["messages"][0].artifact["human_input"]
    ids = [o["id"] for o in kart["options"]]
    assert OPTION_SESSION not in ids, "taban katmaninda kalici izin sunulmamali"
    assert OPTION_ONCE in ids
    assert len(ids) == 2


def test_oturum_izni_tabani_acamaz():
    """En kritik guvence: gecmisten gelen bir oturum karari tabani delmemeli."""
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    sonuc = mw.wrap_tool_call(istek("bash", "rm -rf /", [karar(OPTION_SESSION, "rm -rf /")]), sayac)

    assert sayac.cagrildi == 0, "oturum izni tabani deldi"
    assert isinstance(sonuc, Command), "yeniden sorulmadi"


def test_bir_kez_izni_tabanda_calisir_ama_tukenir():
    mw = ApprovalGateMiddleware()
    mesajlar = [karar(OPTION_ONCE, "rm -rf /")]

    ilk = Sayac()
    mw.wrap_tool_call(istek("bash", "rm -rf /", mesajlar), ilk)
    assert ilk.cagrildi == 1, "acik tek seferlik onay calismaliydi"

    ikinci = Sayac()
    sonuc = mw.wrap_tool_call(istek("bash", "rm -rf /", mesajlar), ikinci)
    assert ikinci.cagrildi == 0, "taban izni ikinci kez kullanildi"
    assert isinstance(sonuc, Command)


def test_taban_karti_geri_alinamaz_uyarisi_tasir():
    mw = ApprovalGateMiddleware()
    sonuc = mw.wrap_tool_call(istek("bash", "mkfs.ext4 /dev/sda1"), Sayac())
    kart = sonuc.update["messages"][0].artifact["human_input"]

    assert "GERI ALINAMAZ" in kart["title"]
    assert "geri alinamaz" in kart["context"].lower()
