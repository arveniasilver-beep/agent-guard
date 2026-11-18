"""Onay kapisi testleri: kapinin gercekten kestigini dogrular."""

from dataclasses import dataclass, field
from typing import Any

import pytest
from langgraph.types import Command

from agent_guard.card import OPTION_DENY, OPTION_ONCE, OPTION_SESSION, SOURCE, request_id_for
from agent_guard.middleware import ApprovalGateMiddleware

TABAN = "rm -rf /"          # geri alinamaz: taban katmani
TEHLIKELI = "rm -rf build/"  # riskli ama geri alinabilir
ZARARSIZ = "ls -la"


class SahteMesaj:
    def __init__(self, kwargs=None):
        self.additional_kwargs = kwargs or {}


def karar(option_id: str, command: str) -> SahteMesaj:
    return SahteMesaj({
        "human_input_response": {
            "version": 1, "kind": "human_input_response", "source": SOURCE,
            "request_id": request_id_for(command), "response_kind": "option",
            "option_id": option_id, "value": "x",
        }
    })


@dataclass
class SahteIstek:
    tool_call: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=lambda: {"messages": []})


def istek(ad: str, komut: str | None = None, mesajlar=None, cagri_id="call-1") -> SahteIstek:
    args: dict[str, Any] = {"description": "test"}
    if komut is not None:
        args["command"] = komut
    return SahteIstek(
        tool_call={"name": ad, "args": args, "id": cagri_id},
        state={"messages": mesajlar or []},
    )


class Sayac:
    def __init__(self) -> None:
        self.cagrildi = 0

    def __call__(self, request: Any) -> str:
        self.cagrildi += 1
        return "CALISTI"


@pytest.fixture(autouse=True)
def manuel_mod(monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_MODE", "manual")


# -- kapinin kestigi durumlar -----------------------------------------

def test_karar_yokken_komut_calismaz_ve_kart_gosterilir():
    """En kritik test: handler CAGRILMAMALI, yerine onay karti donmeli."""
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    sonuc = mw.wrap_tool_call(istek("bash", TEHLIKELI), sayac)

    assert sayac.cagrildi == 0, "onay alinmadan komut calisti"
    assert isinstance(sonuc, Command), "tur bitirilmedi"
    assert sonuc.goto == "__end__"

    mesaj = sonuc.update["messages"][0]
    kart = mesaj.artifact["human_input"]
    assert kart["kind"] == "human_input_request"
    assert kart["source"] == SOURCE
    assert TEHLIKELI in kart["context"]
    assert len(kart["options"]) == 3, "tehlikeli seviyede 3 secenek olmali"


def test_kullanici_reddedince_komut_calismaz():
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    sonuc = mw.wrap_tool_call(istek("bash", TEHLIKELI, [karar(OPTION_DENY, TEHLIKELI)]), sayac)

    assert sayac.cagrildi == 0, "reddedilen komut calisti"
    assert sonuc.status == "error"
    assert "REDDEDILDI" in sonuc.content


# -- kapinin gecirdigi durumlar ---------------------------------------

def test_kullanici_onaylayinca_komut_calisir():
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    sonuc = mw.wrap_tool_call(istek("bash", TEHLIKELI, [karar(OPTION_SESSION, TEHLIKELI)]), sayac)

    assert sayac.cagrildi == 1, "onaylanan komut calismadi"
    assert sonuc == "CALISTI"


def test_zararsiz_komut_sorulmadan_gecer():
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    assert mw.wrap_tool_call(istek("bash", ZARARSIZ), sayac) == "CALISTI"
    assert sayac.cagrildi == 1


def test_kapi_disindaki_arac_etkilenmez():
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    mw.wrap_tool_call(istek("read_file", TEHLIKELI), sayac)
    assert sayac.cagrildi == 1


def test_komut_argumani_yoksa_gecer():
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    mw.wrap_tool_call(istek("bash", None), sayac)
    assert sayac.cagrildi == 1


# -- 'bir kez' semantigi ----------------------------------------------

def test_bir_kez_onayi_ikinci_denemede_tukenir():
    """'Bir kez' kalici onaya donusmemeli."""
    mw = ApprovalGateMiddleware()
    mesajlar = [karar(OPTION_ONCE, TEHLIKELI)]

    ilk = Sayac()
    mw.wrap_tool_call(istek("bash", TEHLIKELI, mesajlar), ilk)
    assert ilk.cagrildi == 1, "ilk denemede calismaliydi"

    ikinci = Sayac()
    sonuc = mw.wrap_tool_call(istek("bash", TEHLIKELI, mesajlar), ikinci)
    assert ikinci.cagrildi == 0, "'bir kez' onayi ikinci kez kullanildi"
    assert isinstance(sonuc, Command), "yeniden sorulmadi"


def test_oturum_onayi_tekrar_tekrar_gecerli():
    mw = ApprovalGateMiddleware()
    mesajlar = [karar(OPTION_SESSION, TEHLIKELI)]
    for _ in range(3):
        sayac = Sayac()
        mw.wrap_tool_call(istek("bash", TEHLIKELI, mesajlar), sayac)
        assert sayac.cagrildi == 1


def test_baska_komutun_onayi_sizmaz():
    """Bir komutu onaylamak baska tehlikeli komutu serbest birakmamali."""
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    sonuc = mw.wrap_tool_call(istek("bash", "rm -rf /etc", [karar(OPTION_SESSION, TEHLIKELI)]), sayac)

    assert sayac.cagrildi == 0
    assert isinstance(sonuc, Command)


# -- mod davranisi -----------------------------------------------------

def test_off_modu_kapiyi_devre_disi_birakir(monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_MODE", "off")
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    mw.wrap_tool_call(istek("bash", TEHLIKELI), sayac)
    assert sayac.cagrildi == 1


def test_gecersiz_mod_manuel_e_duser(monkeypatch):
    """Yazim hatasi kapiyi sessizce acmamali."""
    monkeypatch.setenv("AGENT_GUARD_MODE", "sacmalik")
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    mw.wrap_tool_call(istek("bash", TEHLIKELI), sayac)
    assert sayac.cagrildi == 0


def test_mod_tanimsizsa_manuel(monkeypatch):
    monkeypatch.delenv("AGENT_GUARD_MODE", raising=False)
    mw, sayac = ApprovalGateMiddleware(), Sayac()
    mw.wrap_tool_call(istek("bash", TEHLIKELI), sayac)
    assert sayac.cagrildi == 0


# -- asenkron yol ------------------------------------------------------

@pytest.mark.asyncio
async def test_asenkron_yol_da_keser():
    """Gateway asenkron calisir; senkronu kapatip asenkronu acik birakmak
    kapiyi tamamen etkisiz kilardi."""
    mw = ApprovalGateMiddleware()
    cagrildi = 0

    async def handler(request):
        nonlocal cagrildi
        cagrildi += 1
        return "CALISTI"

    sonuc = await mw.awrap_tool_call(istek("bash", TEHLIKELI), handler)
    assert cagrildi == 0
    assert isinstance(sonuc, Command)


@pytest.mark.asyncio
async def test_asenkron_yol_onayi_gecirir():
    mw = ApprovalGateMiddleware()
    cagrildi = 0

    async def handler(request):
        nonlocal cagrildi
        cagrildi += 1
        return "CALISTI"

    sonuc = await mw.awrap_tool_call(istek("bash", TEHLIKELI, [karar(OPTION_SESSION, TEHLIKELI)]), handler)
    assert cagrildi == 1
    assert sonuc == "CALISTI"
