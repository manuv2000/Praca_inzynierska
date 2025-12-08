
# PLC Security Simulation – Quick README

Krótki przewodnik po repo. Ma wystarczyć, by każdy z zespołu zrozumiał **co robi który plik** i **jak tego używać** – bez wchodzenia w zbędne szczegóły.

> **Uruchamianie polecane:**  
> - Start przechwytywania: `capture\scripts\capture_start.bat`  
> - Scenariusz: `python -m injector.orchestrator`  
> - Stop przechwytywania: `capture\scripts\capture_stop.bat`

---

## injector/

### `logging_setup.py`
Ustawia spójne logowanie (timestamp, poziom, nazwa modułu).  
**Użycie:** `from .logging_setup import setup; setup("INFO")`.

---

### `modbus_util.py`
Wspólna warstwa do Modbus/TCP:
- `modbus_client(host, port)` – kontekst z automatycznym `connect/close`.
- `RetryingClient` – metody `read_hr`, `write_hr`, `write_hrs` z prostym retry.
Dzięki temu wszystkie moduły korzystają z **tego samego**, stabilnego klienta.

---

### `health_check.py`
Szybki test PLC:
- sprawdza „heartbeat” (HR0),
- mierzy czasy odpowiedzi (mean/p95).  
**Cel:** wiedzieć, że runtime działa i jakie są opóźnienia przed testem.

---

### `hmi_master.py`
Symuluje **HMI/SCADA**:
- stałe połączenie,
- cykliczne odczyty blokowe (FC3) z małym jitterem,
- rzadkie zapisy (np. setpoint).  
Służy jako **normalny baseline** ruchu.

---

### `generate_normal.py`
Lekki „drugi klient”:
- okresowe odczyty,
- czasem zapis w dozwolonym zakresie (policy guard + read-back),
- tryb `dry_run` bez zapisów.  
Daje trochę różnorodności do normalnego ruchu.

---

### `markers.py`
Jedna funkcja `mark(...)` zapisująca **znacznik** do `%MW10`.  
Służy do wyznaczania **start/stop** kroków w pcap i w `events.json`.

---

### `orchestrator.py`
Główny sterownik scenariusza:
- czyta `scenarios/scenario.yaml`,
- uruchamia kroki (tło: `hmi_master`/`normal`; foreground: ataki),
- wysyła markery przed/po każdym kroku,
- zapisuje oś czasu do `scenarios/events.json`.  
**Uruchom:** `python -m injector.orchestrator`.

---

## injector/attacks/

### `scan_readonly.py`
**Skan odczytowy** (bez zapisów): FC3/FC1 po zakresach adresów, zlicza wyjątki.  
Emuluje rozpoznanie zasobów bez zmiany stanu PLC.

---

### `scan.py`
**Skan inwazyjny** (może zawierać zapisy).  
Parametr `safe=True` wycina zapisy; `False` – dopuszcza FC6/FC16.  
Używamy ostrożnie – tylko w labie.

---

### `write_injection.py`
**Wymuszone zapisy** do wybranego rejestru (np. `%MW2`), z tempem `qps` i opcją weryfikacji (read-back).  
Modelowo czysty przykład „command injection”.

---

### `network_scan.py`
Szybki test TCP: sprawdza, czy port 502 jest **otwarty** (3-way handshake), mierzy `connect()` RTT.  
Nie wysyła żadnych ramek Modbus.

---

## features/

### `pcap_to_json.py`
Konwersja `.pcap/.pcapng` → **JSONL** przy pomocy **TShark**.  
Wyciąga: czas, IP/porty, długości TCP, pola Modbus (func_code, address, exception).

---

### `feature_modbus.py`
Buduje **cechy w oknach czasowych** (np. 1 s) z JSONL:
- liczniki funkcji (FC1/3/5/6/15/16),
- wyjątki,
- statystyki adresów (min/max/span),
- IAT (średnia/p95),
- rozmiary ramek, proste ratio kierunku.  
Wynik zapisujemy do Parquet.

---

### `build_dataset.py`
Łączy cechy z **etykietami** z `events.json`:
- okna nachodzące na krok ataku dostają jego label,
- reszta w czasie baseline → `normal`.  
Zapis do `data/features.parquet` – gotowe do trenowania.

---

## capture/scripts/

### `capture_start.bat`
Uruchamia **dumpcap** na wybranym interfejsie (najczęściej Npcap Loopback / Ethernet).  
Filtr zwykle: `tcp port 502`. Zapis z rotacją do `capture\pcap\...`.

### `capture_stop.bat`
Kończy działanie `dumpcap` (taskkill). Użyj po scenariuszu.

---

## scenarios/

### `scenario.yaml`
Opis scenariusza:
- `global`: `plc_host`, `plc_port`, `unit_id`,
- `run`: lista kroków: `kind`, `start_after_s`, `duration_s`, `params`.  
**Kinds:** `hmi_master`, `normal`, `scan_readonly`, `scan`, `write_injection`, `network_scan`.

---

## Minimalny przebieg (TL;DR)

1. Start przechwytywania: `capture\scripts\capture_start.bat`  
2. Sprawdź PLC: `python -m injector.health_check`  
3. Uruchom scenariusz: `python -m injector.orchestrator`  
4. Stop przechwytywania: `capture\scripts\capture_stop.bat`  
5. ETL:  
   - `python features\pcap_to_json.py <pcap> features\pcap_json.jsonl`  
   - `python features\feature_modbus.py --jsonl features\pcap_json.jsonl --out data\features_modbus.parquet`  
   - `python features\build_dataset.py --features data\features_modbus.parquet --events scenarios\events.json --out data\features.parquet`

# Dłuższa Wersja
### `injector/logging_setup.py`

**Rola:** Mały helper do spójnej konfiguracji logowania dla wszystkich skryptów (HMI, ataki, orchestrator). Zapewnia timestamp, poziom logu, nazwę modułu i treść w każdej linii.

**API:**
```python
# injector/logging_setup.py
import logging, sys

def setup(level: str = "INFO") -> None:
    """Konfiguracja root loggera do wyjścia na konsolę."""
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
```
 **Użycie:**
 ```python
from .logging_setup import setup
import logging

setup("INFO")  # albo "DEBUG"
log = logging.getLogger("plc.hmi")
log.info("HMI started")

```
### `injector/modbus_util.py`

**Rola:** Bezpieczna warstwa dostępu do Modbus/TCP z retry i czytelnym API. Zapewnia:
- kontekst menedżera połączenia (`modbus_client(...)`)
- klient z automatycznymi ponowieniami (`RetryingClient`)
- wygodne metody: `read_hr`, `write_hr`, `write_hrs`

**API (skrót):**
```python
# injector/modbus_util.py
import time, logging
from contextlib import contextmanager
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

log = logging.getLogger("plc.injector")

@contextmanager
def modbus_client(host: str, port: int, timeout: float = 1.5, retries: int = 3):
    """
    Kontekst połączenia Modbus TCP. Dba o connect/close.
    Zwraca RetryingClient z automatycznymi ponowieniami wywołań.
    """
    c = ModbusTcpClient(host=host, port=port, timeout=timeout)
    if not c.connect():
        raise RuntimeError(f"Cannot connect to {host}:{port}")
    try:
        yield RetryingClient(c, retries)
    finally:
        try: c.close()
        except: pass

class RetryingClient:
    def __init__(self, client: ModbusTcpClient, retries: int):
        self.c = client
        self.retries = retries

    def _try(self, fn, *a, **kw):
        last = None
        for i in range(self.retries):
            try:
                res = fn(*a, **kw)
                if hasattr(res, "isError") and res.isError():
                    raise ModbusException(res)
                return res
            except Exception as e:
                last = e
                time.sleep(0.05 * (i + 1))  # krótki backoff
        raise last

    # Wygodne skróty dla Holding Registers:
    def read_hr(self, addr: int, count: int = 1, unit: int = 1):
        return self._try(self.c.read_holding_registers, addr, count=count, unit=unit)

    def write_hr(self, addr: int, value: int, unit: int = 1):
        return self._try(self.c.write_register, addr, value=value, unit=unit)

    def write_hrs(self, addr: int, values: list[int], unit: int = 1):
        return self._try(self.c.write_registers, addr, values=values, unit=unit)
```
 **Użycie:**
 ```python
from .modbus_util import modbus_client

# Jednorazowy odczyt 8 rejestrów od adresu 0
with modbus_client("127.0.0.1", 502, timeout=1.5, retries=3) as c:
    rr = c.read_hr(0, count=8, unit=1)
    vals = rr.registers  # lista int

# Zapis pojedynczego rejestru + read-back weryfikacja
with modbus_client("127.0.0.1", 502) as c:
    c.write_hr(2, 42, unit=1)
    rb = c.read_hr(1, count=1, unit=1).registers[0]  # np. HR1 = mirror w PLC
    assert rb == 42, f"Write-readback mismatch: {rb} != 42"

```
### `injector/health_check.py`

**Rola:** Szybki test „czy PLC żyje” i jaka jest bazowa latencja Modbus/TCP. Uruchamiaj przed scenariuszami.

**Co robi:**
- Łączy się z OpenPLC przez `modbus_client`.
- Sprawdza, czy **HR0** (heartbeat) zwiększa się między dwoma odczytami → potwierdza, że program PLC i task działają.
- Mierzy round-trip latency dla serii odczytów i raportuje **mean** oraz **p95** (ms).

**Główna logika (skrót):**
```python
from .logging_setup import setup
from .modbus_util import modbus_client
import time, statistics as stats

def ping_hr0(host="127.0.0.1", port=502, unit=1, samples=20):
    setup("INFO")
    lats=[]
    with modbus_client(host, port) as c:
        r0 = c.read_hr(0, count=1, unit=unit).registers[0]  # HR0
        time.sleep(0.2)
        r1 = c.read_hr(0, count=1, unit=unit).registers[0]
        assert r1 != r0, "HR0 not incrementing (PLC/task/modbus off?)"
        for _ in range(samples):
            t0 = time.perf_counter()
            c.read_hr(0, count=1, unit=unit)
            lats.append((time.perf_counter()-t0)*1000)
    print(f"Latency ms: mean={stats.mean(lats):.2f} p95={stats.quantiles(lats, n=20)[18]:.2f}")
```
### `injector/hmi_master.py`

**Rola:** Emuluje typowego klienta HMI/SCADA (Modbus/TCP master) – jedno **stałe połączenie TCP**, cykliczne **odczyty blokowe** (FC3) z drobnym jitterem i okazjonalnym zapisem (np. setpoint). Daje „życiowy” baseline ruchu.

**Co robi:**
- Utrzymuje **persistent connection** do PLC (port 502).
- W każdej pętli odczytuje **bloki rejestrów** (np. `(start=0,count=16)`, `(32,16)`) dla **kilku UnitID** (np. `1, 2`).
- Dodaje **jitter** 5–15 ms do okresu zapytań (bazowo np. 100 ms), by uniknąć idealnej regularności.
- Co jakiś czas wykonuje **rzadki zapis** (np. `HR4` – setpoint), aby zasymulować zmianę nastawy.
- Co kilkadziesiąt minut robi **reconnect**, jak realne sterownie po błędzie/serwisie.

**Najważniejsze parametry:**
- `units=(1,2)` – lista UnitID, które odpytuje ten sam master.
- `blocks=((0,16),(32,16))` – lista bloków do FC3 (start, count).
- `base_period_ms=100` + `jitter_ms=10` – tempo cyklu odczytów.
- `reconnect_every_s=1800` – po ilu sekundach wymusić ponowne połączenie.
- `plc_host="127.0.0.1"`, `plc_port=502` – adres PLC (OpenPLC Runtime).

**Użycie:**
- Uruchamiany przez **orchestrator** jako krok typu `hmi_master` (zwykle **w tle**, `duration_s: 0`).
- Można też uruchomić ręcznie: `python -m injector.hmi_master` (jeśli plik ma `if __name__ == "__main__": run(...)`).

**Dlaczego ważne:**
- Tworzy „normalny” ruch bardzo zbliżony do realnego HMI: stała sesja TCP, odczyty blokowe, jitter i okazjonalne zapisy.
- Pozwala trenować i testować model na bazie nie-idealnie regularnych okien (lepsza generalizacja).

**Wskazówki:**
- **Bloki odczytu** dobierz do mapy rejestrów z programu ST (np. MW0..MW15, MW32..MW47).
- **UnitID** > 1 przydaje się, by zasymulować gateway/koncentrator (kilka urządzeń pod jednym IP).
- **Jitter** niewielki, ale niezerowy – unika artefaktów „idealnej siatki czasu”.
- **Zapis setpointu** rób rzadko (np. 1% cykli), w dozwolonym zakresie polityki (np. 0–100), żeby baseline nie był „czysty jak łza”, ale też nie przypominał ataku.
- Monitoruj p95 latencji z `health_check.py`; jeśli rośnie, zmniejsz `blocks` lub wydłuż `base_period_ms`.

**Interakcja z PLC (ST):**
- Odczyty: HR0.. (heart beat, PV itd.) w zadanych blokach.
- Sporadyczny zapis: `HR4` (setpoint) – PLC przetwarza go i PV (`HR5`) podąża z inercją.

**Typowe pułapki:**
- Zbyt duże `count` w blokach ⇒ exception (legalne, ale niepotrzebne w baseline).
- Zbyt niski okres przy wielu UnitID/blokach ⇒ przeciążenie runtime’u (sprawdzaj p95).
- Odpalanie wielu „HMI” równocześnie bez potrzeby ⇒ nienaturalny baseline.

### `injector/generate_normal.py`

**Rola:** Lekki generator „zwykłego” ruchu Modbus/TCP — okresowe odczyty + okazjonalne zapisy. Działa jako drugi, prostszy klient (np. „maintenance laptop”) obok `hmi_master`. Ma wbudowane:
- **policy guard** – nie zapisuje wartości spoza dozwolonego zakresu,
- **read-back verification** – po zapisie sprawdza, czy PLC potwierdził wartość (`HR1` jako mirror `HR2`),
- tryb **`dry_run`** – loguje, co by zrobił, ale nie wysyła zapisów.

**Główne parametry:**
- `plc_host`, `plc_port`, `unit_id` – adres PLC/UnitID.
- `read_period_ms` – okres odczytów (np. 100 ms).
- `read_addr`, `read_count` – zakres odczytu FC3 (Holding Registers).
- `write_prob` – prawdopodobieństwo pojedynczego zapisu w cyklu (np. 0.03).
- `write_addr`, `write_range` – adres zapisu i dozwolony zakres losowanej wartości.
- `policy=(lo, hi)` – **biała lista** wartości dopuszczonych do zapisu (poza nią: tylko log ostrzegawczy).
- `dry_run=False` – gdy `True`, nie wysyła zapisów, tylko raportuje.

**Logika działania (skrót):**
1. Otwiera stabilne połączenie Modbus (wrapper z retry).
2. Co `read_period_ms`: `read_hr(read_addr, read_count)` — emuluje cykliczny odczyt.
3. Z prawd. `write_prob`: losuje wartość z `write_range`.
   - Jeśli **poza** `policy` → **nie** zapisuje (log **WARNING**).
   - Jeśli w `policy` i nie `dry_run` → `write_hr(write_addr, value)` oraz **weryfikacja read-back**: `HR1` powinien równać się `value`. Mismatch → log **ERROR**.
4. Pętla trwa dopóki proces działa (przeznaczony do uruchamiania w tle).

**Użycie:**
- Jako krok tła w scenariuszu (opcjonalnie, obok `hmi_master`):
  ```yaml
  - name: maintenance_client
    kind: normal
    duration_s: 0
    params:
      read_period_ms: 120
      read_addr: 0
      read_count: 8
      write_prob: 0.02
      write_addr: 2
      write_range: [0, 100]
      policy: [0, 100]
      dry_run: false

### `injector/attacks/write_injection.py`

**Rola:** Generuje **nieautoryzowane zapisy** (FC6/FC16 – w tej wersji FC6) do wybranego rejestru, aby zasymulować atak polegający na wymuszeniu wartości procesu. Ma wbudowaną weryfikację odczytem zwrotnym.

**Zachowanie:**
- Utrzymuje połączenie Modbus/TCP i przez zadany czas wysyła serię zapisów do `target_addr`.
- Tempo kontrolowane parametrem **`qps`** (żądania/sekundę).
- Po każdym zapisie (gdy `verify=True`) wykonuje odczyt zwrotny rejestru **HR1** (mirror w PLC) i loguje zgodność.

**Najważniejsze parametry:**
- `plc_host`, `plc_port`, `unit_id` – adres PLC/UnitID.
- `target_addr` – adres rejestru docelowego (np. `%MW2` → `2`).
- `value` – wymuszana wartość (np. `999`).
- `duration_s` – czas trwania ataku w sekundach.
- `qps` – tempo zapisów (np. `10`).
- `verify` – `True/False`, czy wykonywać read-back (odczyt `HR1`).

**API (skrót):**
```python
# injector/attacks/write_injection.py
def run(plc_host, plc_port, unit_id,
        target_addr=2, value=999,
        duration_s=30, qps=20, verify=True) -> None:
    """Wysyła powtarzane FC6 do target_addr przez duration_s w tempie qps.
    Przy verify=True sprawdza mirror w HR1 i loguje mismatch."""
```

### `injector/attacks/scan_readonly.py`

**Rola:** Bezpieczny „czytający” skaner Modbus/TCP (bez zapisów). Służy do emulacji rozpoznania zasobów: enumeruje adresy i reaguje na wyjątki (illegal function/address), generując charakterystyczny ślad skanowania w ruchu.

**Co robi:**
- Ustanawia połączenie Modbus/TCP i przez określony czas wysyła **tylko odczyty** (FC1 – Coils oraz/lub FC3 – Holding Registers).
- Przechodzi po zadanych **zakresach adresów** (np. `[[0, 200]]`) z ograniczeniem tempa **`qps`** (requests per second).
- Zlicza **wyjątki/time-outy** jako miarę „szorstkości” skanu (skany zwykle produkują więcej błędów niż HMI).

**Parametry (najważniejsze):**
- `plc_host`, `plc_port`, `unit_id` – cel skanowania.
- `addr_ranges` – lista przedziałów adresów, np. `[[0, 200]]`.
- `qps` – maksymalna liczba żądań na sekundę (np. 30).
- `duration_s` – maksymalny czas skanowania (np. 30–60 s).
- (opcjonalnie) `try_fc` – które funkcje odczytu testować, domyślnie `(1, 3)`.

**Zachowanie na poziomie protokołu:**
- Wysyła FC3 (read holding registers) `count=1` dla kolejnych adresów; opcjonalnie FC1 (read coils).
- Błędy protokołu (illegal address/function) są łapane i zliczane – to naturalny sygnał „scan” dla cech `exc_cnt` i rozkładu funkcji.
- Brak zapisów ⇒ **zero ryzyka** zmian stanu PLC w baseline’owej fazie rozpoznania.

**Użycie w scenariuszu:**
```yaml
- name: scan_ro
  kind: scan_readonly
  start_after_s: 60
  duration_s: 45
  params:
    addr_ranges: [[0, 200]]
    qps: 30
    # try_fc: [1, 3]  # opcjonalnie
```

### `injector/attacks/scan.py` (intrusive)

**Rola:** Inwazyjny skaner protokołowy Modbus/TCP – oprócz odczytów (FC1/FC3) może wykonywać **zapisy** (FC5/FC6/FC15/FC16). Służy do generowania ruchu „atakowo-skanerskiego”, który **ingeruje w stan PLC** (świadomie, w labie).

**Co robi:**
- Utrzymuje połączenie Modbus/TCP i w zadanym czasie wysyła żądania o wskazanych funkcjach.
- Dla odczytów: przechodzi po zakresach adresów (`addr_ranges`) – sequential/random (w implementacji możesz włączyć).
- Dla zapisów: generuje wartości (np. losowe lub stałe) i uderza w podany adres (lub w przemiataną przestrzeń), co powoduje **zmianę rejestrów** po stronie PLC.
- Pacing przez **`qps`** (requests/second), aby kontrolować agresywność.
- Zlicza wyjątki i time-outy; loguje błędy.

**Parametry (główne):**
- `plc_host`, `plc_port`, `unit_id` – cel.
- `addr_ranges` – lista przedziałów adresów (np. `[[0, 200]]`).
- `function_codes` – lista FC do użycia (np. `[3, 6, 16]`).
- `qps` – tempo zapytań (np. `30`).
- `duration_s` – czas trwania skanu/ataku (np. `30`).
- `safe` – **domyślnie `True`**: filtruje funkcje zapisujące (FC5/6/15/16), aby nie modyfikować PLC; ustaw `False`, gdy chcesz faktyczne zapisy (inwazyjne).

**Zachowanie (protokół):**
- FC3/FC1: czyta pojedyncze rejestry/cewki kolejno po adresach → generuje typowe dla skanu wzorce (dużo wyjątków, wysoki `fc3`/`fc1`, duży `addr_span`).
- FC6/FC16 (gdy `safe=False`): zapisuje wartości do rejestrów – **zmienia stan PLC** (zawsze tylko w izolowanym labie!).
- Transakcyjnie: rosnący MBAP Transaction ID, jedna sesja TCP lub krótkie reconnecty (opcjonalnie).

**Użycie w scenariuszu (orchestrator):**
```yaml
- name: scan_intrusive
  kind: scan
  start_after_s: 120
  duration_s: 30
  params:
    addr_ranges: [[0, 200]]
    function_codes: [3, 6]   # odczyt + zapis
    qps: 30
    safe: false              # UWAGA: to włączy zapisy!
```

### `injector/attacks/network_scan.py`

**Rola:** Prosty, **nie-Modbusowy** skaner sieciowy – sprawdza dostępność portów (np. 502/TCP dla Modbus) i mierzy RTT po nawiązaniu gniazda TCP. Służy do generowania śladu „rozpoznania sieci” bez ingerencji w protokół PLC.

**Co robi:**
- Próbuje połączyć się z hostem na zadanych portach (domyślnie `502`).
- Raportuje, czy port jest **otwarty** oraz przybliżony **czas RTT** (od `connect()`).
- **Nie** wysyła żadnych ramek Modbus – tylko TCP 3-way handshake.

**Parametry:**
- `host` – adres IP/DNS celu (np. `"127.0.0.1"`).
- `ports` – krotka/lista portów do sprawdzenia, np. `(502,)` lub `(502, 80, 443)`.
- `timeout` – limit czasu na próbę połączenia (np. `1.0` s).

**Zachowanie w ruchu:**
- Dla każdego portu: SYN → SYN/ACK (jeśli otwarty) → ACK → natychmiastowe zamknięcie gniazda.
- W pcap widać krótkie, pojedyncze sesje TCP bez danych aplikacyjnych.

**Użycie w scenariuszu (orchestrator):**
```yaml
- name: net_scan
  kind: network_scan
  start_after_s: 20
  duration_s: 0          # jednorazowy przebieg (brak pętli czasu)
  params:
    host: "127.0.0.1"
    ports: [502, 80, 443]
    timeout: 1.0
```

### `injector/markers.py`

**Rola:** Jedno, małe API do **znakowania** przebiegów w PLC (Modbus/TCP) – zapisuje wartości „start/stop” do wskazanego rejestru (np. `%MW10`). Dzięki temu w Wireshark/TShark oraz w `events.json` masz **dokładne kotwice czasowe** dla każdego kroku scenariusza.

**API:**
```python
# injector/markers.py
from .modbus_util import modbus_client

def mark(host: str, port: int, unit: int, value: int, addr: int = 10) -> None:
    """
    Zapisuje 'value' do rejestru holding (domyślnie %MW10 ↔ addr=10).
    Używane przez orchestrator do start/stop stepów.
    """
    with modbus_client(host, port) as c:
        c.write_hr(addr, value, unit=unit)
```

### `injector/orchestrator.py`

**Rola:** Steruje całym przebiegiem scenariusza. Wczytuje `scenarios/scenario.yaml`, odpala kroki (HMI/baseline w tle, ataki w trybie „foreground”), **znakuje** start/stop każdego kroku w PLC (markery na `%MW10`) i zapisuje **oś czasu ground truth** do `scenarios/events.json`.

**Najważniejsze funkcje:**
- **Mapa `kind → moduł`:**
  - `hmi_master` → `injector.hmi_master` (tło)
  - `normal` → `injector.generate_normal` (tło)
  - ataki → `injector.attacks.<kind>` (foreground: `scan_readonly`, `scan`, `write_injection`, `network_scan`)
- **Markery kroków:** przed startem kroku zapis `0xB000 + idx`, po zakończeniu `0xD000 + idx` do `%MW10` (domyślnie `addr=10`).
- **Tło vs foreground:** kroki z `duration_s: 0` lub rodzaje z listy tła uruchamiane jako **daemon threads**; pozostałe synchronicznie na zadaną długość.
- **Zapisywanie osi czasu:** tworzy `scenarios/events.json` z polami: `index`, `name`, `label`, `start`, `end`, `start_marker`, `end_marker`, `marker_addr`.

**Konfiguracja (`scenarios/scenario.yaml` – przykład):**
```yaml
global:
  plc_host: "127.0.0.1"
  plc_port: 502
  unit_id: 1

run:
  - name: hmi
    kind: hmi_master
    duration_s: 0

  - name: scan_ro
    kind: scan_readonly
    start_after_s: 60
    duration_s: 45
    params:
      addr_ranges: [[0, 200]]
      qps: 30

  - name: write_attack
    kind: write_injection
    start_after_s: 140
    duration_s: 20
    params:
      target_addr: 2
      value: 999
      qps: 10
      verify: true
```

### `features/pcap_to_json.py`

**Rola:** Konwersja przechwyconych pakietów (`.pcap/.pcapng`) do **liniowego JSONL** (po 1 rekordzie na pakiet) z polami zdekodowanymi przez **TShark** (Modbus/TCP + metadane). To pierwszy krok ETL przed budową cech.

**Wymagania:**
- Zainstalowany **Wireshark/TShark** (w PATH).
- Plik wejściowy: `capture/pcap/…/*.pcap(ng)`.
- Wyjście: np. `features/pcap_json.jsonl`.

**Co wyciąga:**
- Czas: `frame.time_epoch`
- Warstwa sieci/transport: `ip.src`, `ip.dst`, `tcp.srcport`, `tcp.dstport`, `tcp.len`
- Modbus (jeśli obecny): `modbus.func_code`, `modbus.reference_num` (adres rejestru), `modbus.exception_code`, `modbus.length`, itp.
- Dodatkowe pola TCP (np. `tcp.flags`) – zależnie od konfiguracji.

**Użycie:**
```bash
python features/pcap_to_json.py input.pcapng features/pcap_json.jsonl
# lub (domyślne ścieżki w repo)
python features/pcap_to_json.py capture/pcap/latest.pcap features/pcap_json.jsonl
```

### `features/feature_modbus.py`

**Rola:** Z pliku JSONL z TShark (`pcap_to_json.py`) buduje **cechy czasowe** Modbus/TCP w stałych oknach (np. 1 s) – agregowane per strumień `(src_ip, dst_ip, dst_port, unit_id)` i gotowe do łączenia z etykietami z `events.json`.

**Wejście → Wyjście:**
- **Wejście:** `features/pcap_json.jsonl` (1 linia = 1 pakiet, z polami Modbus/TCP).
- **Wyjście:** tabela (np. Pandas DataFrame / Parquet) z cechami per okno (`ts_bin`) i strumień, np. `data/features.parquet`.

**Sposób grupowania:**
- Klucz strumienia: `(ip.src, ip.dst, tcp.dstport, modbus.unit_id)`
- Oś czasu: binowanie do **1 s** (lub parametryzowane) na podstawie `frame.time_epoch`.

**Zestaw cech (skrót – per okno):**
- **Zliczenia:** `n_pkts`, `n_req`, `n_resp`, `exc_cnt`
- **Kody funkcji (histogram):** `fc1`, `fc3`, `fc5`, `fc6`, `fc15`, `fc16`, `fc_other`
- **Adresy rejestrów:** `addr_min`, `addr_max`, `addr_span` (= max−min w oknie), `addr_nuniq`
- **Timing (IAT):** `iat_mean_ms`, `iat_p95_ms`, `iat_std_ms` (z różnic czasów pomiędzy pakietami klienta)
- **Rozmiary:** `len_mean`, `len_std`, `len_p95`
- **Kierunek:** `c2s_ratio` (requests/responses albo bajty C→S / S→C)
- **UnitID:** `unitid_nuniq` (jeśli brak pola, fallback = 1)

**Logika (w zarysie):**
1. Parsuje JSONL i filtruje `tcp.port==502` (jeśli nie zrobiono tego wcześniej).
2. Ekstrahuje pola: `time`, `src/dst`, `tcp.len`, `modbus.func_code`, `modbus.reference_num`, `modbus.exception_code`, `modbus.unit_id`.
3. Tworzy `ts_bin = floor(time / window) * window` i grupuje po `(stream_key, ts_bin)`.
4. Liczy histogram funkcji, statystyki IAT (tylko dla zapytań klienta), statystyki adresów i rozmiarów.
5. Zwraca ramkę z cechami (lub zapisuje do Parquet).

**Użycie (przykład):**
```bash
python features/feature_modbus.py \
  --jsonl features/pcap_json.jsonl \
  --out data/features.parquet \
  --window 1.0
```

### `features/build_dataset.py`

**Rola:** Łączy surowe cechy z pakietów (`features/pcap_json.jsonl` → cechy z `feature_modbus.py`) z **ground truth** ze `scenarios/events.json`, tworząc finalny zbiór do trenowania (np. `data/features.parquet`).

**Wejście:**
- `features/pcap_json.jsonl` → przetworzone przez `feature_modbus.py` do okien czasowych (DF z kolumną `ts_bin`).
- `scenarios/events.json` → oś czasu kroków scenariusza (`name`, `label`, `start`, `end` lub `null` dla tła, markery).

**Co robi:**
1. **Wczytuje** okna cech (Parquet/CSV/DF) i **wydarzenia** (`events.json`).
2. **Etykietuje okna**: dla każdego okna (`ts_bin`…`ts_bin+window`) sprawdza **przecięcie czasu** z krokami:
   - okna nachodzące na kroki foreground dostają `label` danego kroku,
   - okna poza krokami ataków, ale w czasie działania tła → `normal`.
3. (Opcjonalnie) usuwa/metkuje okna bez Modbus.
4. **Zapisuje** finalny zbiór do `data/features.parquet`.

**Założenia / reguły etykietowania:**
- Czas okna: `[ts_bin, ts_bin + window)` (domyślnie 1 s).
- Krok foreground: `[start, end]` z `events.json`.
- Tło (`hmi_master`, `normal`): brak `end` → traktuj jako cały przebieg (od `session_start` do `session_end`).
- Konflikty (nakładanie wielu kroków foreground, rzadkie): wybierz **najbardziej specyficzną** etykietę (np. priorytet: `write_injection` > `scan` > `scan_readonly` > `normal`) albo oznacz `mixed` i wyklucz z treningu.

**Użycie (przykład):**
```bash
python features/build_dataset.py \
  --features data/features_modbus.parquet \
  --events scenarios/events.json \
  --out data/features.parquet \
  --window 1.0
```

### `capture/scripts/capture_start.bat`

**Rola:** Startuje przechwytywanie ruchu za pomocą **dumpcap** (Wireshark/Npcap) na wskazanym interfejsie, z rotacją plików `.pcapng`. Uruchamiaj **przed** orchestrator’em.

**Wymagania:**
- Zainstalowany **Wireshark** (TShark/dumpcap w PATH).
- **Npcap** z opcją „WinPcap API-compatible Mode”.

**Co robi (typowy schemat):**
- Wybiera interfejs po GUID (`-i \\Device\\NPF_{GUID}`).
- Filtr przechwytywania: np. `tcp port 502` (tylko Modbus/TCP).
- Rotuje pliki: `-b filesize:200000` (≈200 MB) i/lub `-b duration:600` (10 min).
- Zapisuje do `capture\pcap\session_%Y%m%d_%H%M%S_###.pcapng`.

**Użycie:**
1. Znajdź interfejs:  
   ```bat
   dumpcap -D
   ```


### `capture/scripts/capture_stop.bat`

**Rola:** Zatrzymuje przechwytywanie uruchomione przez `capture_start.bat`. Najprościej: wyszukuje proces `dumpcap.exe` i go kończy.

**Co robi (typowy schemat):**
- Sprawdza, czy działa `dumpcap.exe`.
- Jeśli tak — wysyła polecenie zakończenia procesu (bez zamykania Twojego okna CMD/PowerShell).
- Opcjonalnie wypisuje informację o lokalizacji ostatnich plików `.pcapng`.

**Użycie:**
```bat
capture\scripts\capture_stop.bat
```

### `scenarios/scenario.yaml`

**Rola:** Jedyny plik konfiguracyjny opisujący **przebieg eksperymentu**: globalne parametry PLC oraz listę kroków (baseline/ataki) z harmonogramem, czasem trwania i parametrami modułów. Orchestrator czyta ten plik i **na jego podstawie** uruchamia wszystko we właściwej kolejności.

**Struktura (schemat):**
```yaml
global:
  plc_host: "127.0.0.1"   # adres OpenPLC
  plc_port: 502           # port Modbus/TCP
  unit_id: 1              # Unit ID (slave id)

run:
  - name: <unikalna_nazwa_kroku>
    kind: <typ_kroku>
    start_after_s: <sekundy_od_startu_sesji>   # opcjonalne (domyślnie 0)
    duration_s: <czas_trwania_w_sek>           # 0 lub brak => krok w tle (daemon)
    params:                                     # opcjonalne – nadpisują/uzupełniają global
      <parametry_modułu>
  - ...
```