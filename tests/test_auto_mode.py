"""Auto mod testleri.

Auto mod izin vericidir: yardimci model zararsiz bulursa komut sorulmadan
calisir. Bunu guvenli kilan sey taban katmanidir -- bu dosyadaki en kritik
test, tabanin yargica HIC sorulmadigini dogrulayan testtir.
"""

import pytest
from langgraph.types import Command

from agent_guard.judge import VERDICT_APPROVE, VERDICT_DENY, VERDICT_ESCALATE
from agent_guard.middleware import ApprovalGateMiddleware

from tests.test_middleware import Sayac, istek

TEHLIKELI = "rm -rf build/"
TABAN = "rm -rf /"


class SahteYargic:
    """Cagrildigini ve neyle cagrildigini kaydeden yargic."""

    def __init__(self, karar: str) -> None:
        self.karar = karar
        self.cagrilar: list[tuple[str, str]] = []

    def __call__(self, command: str, description: str) -> str:
        self.cagrilar.append((command, description))
        return self.karar


@pytest.fixture(autouse=True)
def auto_mod(monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_MODE", "auto")


# -- yargic kararlarinin sonuclari ------------------------------------

def test_yargic_onaylayinca_komut_sorulmadan_calisir():
    yargic = SahteYargic(VERDICT_APPROVE)
    mw, sayac = ApprovalGateMiddleware(judge=yargic), Sayac()

    sonuc = mw.wrap_tool_call(istek("bash", TEHLIKELI), sayac)

    assert sayac.cagrildi == 1, "auto onaya ragmen komut calismadi"
    assert sonuc == "CALISTI"
    assert len(yargic.cagrilar) == 1


def test_yargic_reddedince_komut_calismaz():
    yargic = SahteYargic(VERDICT_DENY)
    mw, sayac = ApprovalGateMiddleware(judge=yargic), Sayac()

    sonuc = mw.wrap_tool_call(istek("bash", TEHLIKELI), sayac)

    assert sayac.cagrildi == 0, "yargic reddetti ama komut calisti"
    assert sonuc.status == "error"
    assert "ENGELLENDI" in sonuc.content


def test_yargic_emin_degilse_kullaniciya_sorulur():
    yargic = SahteYargic(VERDICT_ESCALATE)
    mw, sayac = ApprovalGateMiddleware(judge=yargic), Sayac()

    sonuc = mw.wrap_tool_call(istek("bash", TEHLIKELI), sayac)

    assert sayac.cagrildi == 0
    assert isinstance(sonuc, Command), "escalate durumunda kart gosterilmedi"


# -- tabanin dokunulmazligi -------------------------------------------

def test_taban_yargica_HIC_sorulmaz():
    """En kritik guvence: geri alinamaz komut auto modda bile modele sorulmaz.

    Yargic APPROVE dese bile komut calismamali; cunku hic cagrilmamali.
    """
    yargic = SahteYargic(VERDICT_APPROVE)
    mw, sayac = ApprovalGateMiddleware(judge=yargic), Sayac()

    sonuc = mw.wrap_tool_call(istek("bash", TABAN), sayac)

    assert yargic.cagrilar == [], "taban katmani yargica soruldu"
    assert sayac.cagrildi == 0, "taban komutu auto modda calisti"
    assert isinstance(sonuc, Command)


@pytest.mark.parametrize("komut", [
    "rm -rf /", 'rm -rf "/"', "rm -rf $HOME", "mkfs.ext4 /dev/sda1",
    "dd if=/dev/zero of=/dev/sda", "shutdown -h now",
])
def test_tum_taban_komutlari_auto_modda_da_sorulur(komut):
    yargic = SahteYargic(VERDICT_APPROVE)
    mw, sayac = ApprovalGateMiddleware(judge=yargic), Sayac()

    sonuc = mw.wrap_tool_call(istek("bash", komut), sayac)

    assert yargic.cagrilar == [], f"{komut!r} yargica soruldu"
    assert sayac.cagrildi == 0
    assert isinstance(sonuc, Command)


# -- guvenli tarafa dusme ---------------------------------------------

def test_yargic_patlarsa_kullaniciya_sorulur():
    """Model erisilemezse sessizce onaylamak yerine sorulmali."""
    def patlayan(command, description):
        raise RuntimeError("model yok")

    # assess() kendi icinde yakalar; burada dogrudan middleware'e veriyoruz,
    # bu yuzden gercek assess davranisini taklit eden sarmalayici kullan.
    from agent_guard.judge import assess

    mw = ApprovalGateMiddleware(judge=lambda c, d: assess(c, d, model_caller=lambda s, u: (_ for _ in ()).throw(RuntimeError("yok"))))
    sayac = Sayac()

    sonuc = mw.wrap_tool_call(istek("bash", TEHLIKELI), sayac)

    assert sayac.cagrildi == 0, "yargic patladi ama komut calisti"
    assert isinstance(sonuc, Command), "hata durumunda kart gosterilmedi"


def test_zararsiz_komut_yargica_bile_sorulmaz():
    """Desen katmani zararsiz bulduysa model cagrilmamali (maliyet ve gecikme)."""
    yargic = SahteYargic(VERDICT_APPROVE)
    mw, sayac = ApprovalGateMiddleware(judge=yargic), Sayac()

    mw.wrap_tool_call(istek("bash", "ls -la"), sayac)

    assert yargic.cagrilar == [], "zararsiz komut icin model cagrildi"
    assert sayac.cagrildi == 1


def test_manuel_modda_yargic_cagrilmaz(monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_MODE", "manual")
    yargic = SahteYargic(VERDICT_APPROVE)
    mw, sayac = ApprovalGateMiddleware(judge=yargic), Sayac()

    sonuc = mw.wrap_tool_call(istek("bash", TEHLIKELI), sayac)

    assert yargic.cagrilar == [], "manuel modda model cagrildi"
    assert isinstance(sonuc, Command)


def test_off_modunda_yargic_cagrilmaz(monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_MODE", "off")
    yargic = SahteYargic(VERDICT_DENY)
    mw, sayac = ApprovalGateMiddleware(judge=yargic), Sayac()

    mw.wrap_tool_call(istek("bash", TEHLIKELI), sayac)

    assert yargic.cagrilar == []
    assert sayac.cagrildi == 1
