# NodeRooms – versenytársi helyzet és védhető pozíció

## Dokumentumállapot

```text
document_type: Alpha2 strategic supplement
date: 2026-07-30
applies_to: TrustBridge Alpha2 planning and communication
related_handoff: NODEROOMS_TRUSTBRIDGE_ALPHA2_MASTER_HANDOFF_SNAPSHOT_20260730_HU.md
runtime_authority_granted: false
production_enforcement_enabled: false
external_validation_status: pending
```

Ez az Owner által megadott stratégiai kiegészítés a TrustBridge Alpha2
fejlesztési és kommunikációs guardrailje. Nem runtime-contract, nem
versenytársi benchmark-jegyzőkönyv, és önmagában nem bizonyít production
működést vagy piaci elsőbbséget.

A benne szereplő versenytársi megfigyeléseket belső stratégiai inputként kell
kezelni. Nyilvános összehasonlító vagy elsőbbségi állítás csak külön,
forrásolt és aktuális külső validáció után tehető.

## 1. Rövid vezetői következtetés

A Showcase-ben és a tágabb OpenClaw/Agent ökoszisztémában azonosított
versenytársak nem teszik semmissé a NodeRooms jelenlétét. Azt igazolják, hogy
a NodeRooms által célzott problémák valósak és keresettek:

- Agent-identitás és emberi felelősségi lánc;
- pontos, lejáró és visszavonható jogosultság;
- tool-call kapuzás;
- futási bizonyíték és receipt;
- artifact-eredet és runtime-integritás;
- több-Agent és több-Gateway izoláció;
- külsőleg ellenőrizhető működés.

A versenytársak jelenléte ugyanakkor megszünteti annak lehetőségét, hogy a
NodeRooms egy-egy általános építőelemet önmagában egyedinek nevezzen.

Nem tartható önálló egyediségi állításként:

- „Agent Passport”;
- „permission layer”;
- Allow / Ask / Never policy;
- scoped vagy lejáró grant;
- signed vagy portable receipt;
- repository/artifact evidence;
- Agenteknek készült közösségi vagy kommunikációs platform.

A NodeRooms védhető pozíciója a teljes, összekapcsolt bizonyítéklánc:

```text
Verified Owner
→ persistent Agent Passport
→ exact artifact fingerprint
→ Agent/Gateway/runtime binding
→ Owner-approved exact scoped permit
→ canonical intent and dispatch reservation
→ actual provider outcome
→ signed privacy-preserving receipt
→ idempotency and replay protection
→ portable cross-Gateway evidence
```

Az egyes elemek külön-külön már jelen vannak a piacon. A NodeRooms
lehetősége abban van, hogy ezeket egyetlen OpenClaw-native, Owner-bound
authority és evidence rendszerben bizonyítsa.

## 2. Mit jelentenek a most látott versenytársak?

### 2.1 Remit-jellegű policy és grant rendszerek

A belső Showcase-audit alapján már létezik olyan megoldás, amely:

- Allow / Ask / Never jogosultsági modellt használ;
- `before_tool_call` enforcementet végez;
- Agenthez, feladathoz vagy útvonalhoz kötött grantokat ad;
- lejáratot és visszavonást kezel;
- manipulációt jelző vagy tamper-evident naplót készít.

Következmény: a generikus tool-gate, engedélykérés vagy scoped lease önmagában
nem lehet a NodeRooms fő megkülönböztető állítása.

Bizonyítandó NodeRooms-többlet:

- ellenőrzött emberi Ownerhez kötött döntés;
- tartós Passport és Agent-identitás;
- exact artifact és runtime fingerprint;
- exact tool, action, resource és target;
- provider outcome és receipt ugyanabban a láncban;
- replay/idempotency védelem;
- több Gatewayen át hordozható bizonyíték.

### 2.2 AIP- és Agent Receipt-jellegű rendszerek

A belső audit szerint már léteznek:

- aláírt receiptek;
- hash-chain alapú naplók;
- hordozható vagy harness-agnostic bizonyítékok;
- Agent-futtatások utólagos ellenőrzésére szolgáló protokollok.

Következmény: a „signed receipt” vagy „portable receipt” önmagában nem egyedi
termékígéret.

Bizonyítandó NodeRooms-többlet:

- a receipt pontosan mely Owner-döntésből származik;
- mely Passporttal és Agenttel kapcsolódik össze;
- mely exact artifact és runtime futott;
- mely exact permit engedélyezte az akciót;
- mi volt a provider tényleges, hibás vagy `unknown` kimenetele;
- hogyan akadályozta meg a rendszer az ismételt dispatch-et;
- ugyanaz a bizonyíték másik Gatewayen hogyan ellenőrizhető.

### 2.3 Cejel-jellegű offline repository evidence

Az offline repository-evidence megoldás nem feltétlenül közvetlen versenytárs.
Ha kifejezetten nem runtime guard, természetes komponens vagy partner lehet.

Lehetséges, de még nem megvalósított együttműködési határ:

1. A külső rendszer bizonyítja a repository/artifact eredetet.
2. A NodeRooms TrustBridge ezt exact artifact-bemenetként használja.
3. A NodeRooms bizonyítja a futási identitást, Owner-engedélyt, scoped
   permitet és outcome-ot.
4. A verifier a két bizonyítékréteget egy láncban ellenőrzi.

Ezt kész integrációként kommunikálni tilos. Jelenleg kizárólag technikailag
logikus együttműködési lehetőség.

### 2.4 Agentközösségek és kommunikációs platformok

Több projekt tesz lehetővé Agentek közötti kommunikációt, callbacket,
handoffot, közösségi jelenlétet, illetve feladat- vagy approval-kérést.

Következmény: a „közösségi oldal Agenteknek” önmagában nem elégséges
pozicionálás.

A NodeRooms közösségi rétegének értékét az adhatja, hogy a nyilvános vagy
együttműködési identitás mögött ellenőrizhető:

- emberi Owner;
- tartós Passport;
- exact artifact;
- futási authority;
- engedélyezett cselekvés;
- visszakereshető bizonyíték.

## 3. Mi maradt valóban védhető a NodeRoomsban?

### 3.1 Nem egy funkció, hanem végponttól végpontig tartó lánc

A NodeRooms védőárka nem egyetlen technikai elem. A teljes láncot kell
termékként és bizonyítékként kezelni.

| Láncelem | Bizonyítandó állítás |
|---|---|
| Verified Owner | Az Agent mögötti emberi döntési és felelősségi pont ellenőrzött. |
| Persistent Agent Passport | Az Agent identitása nem egy session vagy lokális processz mellékterméke. |
| Exact artifact fingerprint | A ténylegesen futtatott artifact kriptográfiai azonosítója ismert. |
| Agent–Gateway–runtime binding | Bizonyítható, mely Agent mely Gatewayen, milyen runtime-ban és izolált állapottal futott. |
| Owner-approved exact scoped permit | Az engedély exact toolhoz, actionhöz, resource-hoz, targethez, időhöz, darabszámhoz, költséghez és célhoz köthető. |
| Actual provider outcome | Az intent mellett a provider ismert, hibás vagy `unknown` kimenetele is rögzített. |
| Signed privacy-preserving receipt | A bizonyíték ellenőrizhető, de nem szivárogtat tokent, titkot vagy szükségtelen nyers adatot. |
| Idempotency and replay protection | Újraküldés, timeout vagy Gateway-restart nem hozhat létre észrevétlen dupla dispatch-et. |
| Cross-Gateway evidence | A bizonyíték nem csak a keletkezési Gateway lokális állapotában értelmezhető. |

### 3.2 Mi van már meg az Alpha alapjában?

A fő Alpha2 handoff és a repository proofjai alapján contract- vagy
tesztszinten már létezik:

- OpenClaw `before_tool_call` és `after_tool_call` hook;
- exact tool-policy és wildcard-tiltás;
- `off` és `observe` mód;
- adatminimalizált helyi ledger;
- Agent–Passport–Owner–Gateway–runtime kötési contract;
- Owner-reviewed capability és scoped run lease;
- exact tool/action/resource/target és további limitek;
- expiry, revoke, exhaustion és allow-once;
- canonical intent és idempotency;
- dispatch reservation és replay-védelem;
- Ed25519-aláírt receipt contract;
- `unknown` outcome és read-only reconciliation;
- izolált GitHub Draft PR provider-proof;
- több-Agent runtime-izolációs teszt.

Ezek státuszát mindig az exact implementációhoz és proofhoz kell kötni. A
contract-level elem nem kommunikálható productionként bizonyított
funkcióként.

### 3.3 Mi hiányzik még a védhető piaci állításhoz?

Kötelező hiányzó rétegek:

- nyílt `claw-runtime-evidence.v0.1` séma;
- exact artifact és OpenClaw/runtime fingerprint;
- a permit–intent–outcome–receipt lánc egységes evidence-csomagja;
- titokmentes, külső verifier CLI vagy web verifier;
- reprodukálható GitHub és messaging fixture;
- OpenClaw `security.installPolicy` referencia-provider, kezdetben
  `observe-only` módban;
- ClawHub `expected_checks` és külső evidence mapping;
- független fejlesztőktől kapott, reprodukálható teszteredmény;
- későbbi cross-Gateway proof.

Amíg ezek nem készülnek el, tilos azt állítani, hogy a teljes NodeRooms
TrustBridge lánc productionben bizonyított.

## 4. Kommunikációs szabályok

### 4.1 Használható, pontos állítás

> A NodeRooms egy integrált, Ownerhez kötött runtime-authority és
> evidence-láncot épít OpenClaw Agentekhez. Az egyes építőelemek külön-külön
> már léteznek a piacon; a NodeRooms célja ezek összekapcsolása exact
> artifact-, scoped permit-, provider outcome-, replay-védelmi és
> cross-Gateway bizonyítékká.

### 4.2 Jelenleg tiltott, bizonyítatlan állítások

- „világelső”;
- „teljesen egyedi”;
- „az első Agent Passport”;
- „az első signed Agent receipt”;
- „production-safe”;
- „exactly once”;
- „tamper-proof”;
- „minden Gatewayen bizonyított”;
- „ClawHub által hitelesített”;
- „a versenytársak ezt nem tudják”.

### 4.3 Kötelező bizonyítottsági nyelv

Az állításokat az alábbi státuszok egyikével kell minősíteni:

```text
implemented and locally tested
contract-level
isolated provider proof
observe-only
external validation pending
cross-Gateway proof pending
production enforcement disabled
```

## 5. Fejlesztési következmény az Alpha2 számára

Az Alpha2 nem épít újabb generikus permission plugint vagy önálló
receipt-rendszert.

Prioritási sorrend:

1. a meglévő NodeRooms security contractok összekapcsolása;
2. exact artifact/runtime identity hozzáadása;
3. hordozható evidence-csomag létrehozása;
4. független verifier elkészítése;
5. két reprodukálható, valós provider-fixture;
6. több-Agent evidence export;
7. `observe-only` install-policy integráció;
8. külső tesztelők eredményeinek rögzítése;
9. csak ezután partneri vagy szélesebb ClawHub-pozicionálás.

A fejlesztési fókusz nem feature-count, hanem bizonyítható lánczárás.

Minden új Alpha2-feladat kötelező prioritási kérdése:

> Bezárja-e ez a fejlesztés a Verified Owner és a provider outcome közötti
> bizonyítéklánc valamely hiányzó részét?

Ha a válasz nem, a feladat alapértelmezés szerint nem Alpha2-prioritás.

## 6. Külső validációs cél

A következő 30 nap mérnöki célja nem partneri bejelentés, hanem
reprodukálható proof:

- nyílt `claw-runtime-evidence.v0.1` séma;
- exact artifact- és runtime-fingerprint;
- Owner-bound, lejáró execution permit;
- GitHub fixture;
- messaging fixture;
- titokmentes verifier;
- legalább két független OpenClaw-fejlesztő teszteredménye;
- külön shared-Gateway és külön cross-Gateway/isolated-Gateway próba;
- PASS/FAIL acceptance record;
- nyers secret, token és személyes adat nélkül publikálható evidence.

Kilépési feltétel: egy külső fejlesztő ugyanazon exact artifacton megismétli a
tesztet, ugyanazt a normatív fingerprintet kapja, és külső trust anchorral
ellenőrzi az evidence aláírását.

Ezután a NodeRooms már nem pusztán TrustBridge-ötletet állít, hanem külső fél
által ellenőrizhető bizonyítékréteget mutat be.

## 7. Döntési és biztonsági korlátok

Az Alpha2 során változatlanul érvényes:

- a stabil `1.3.0` release-forrást és package identityt nem módosítjuk;
- az Alpha2 külön ágon fejlődik;
- production enforcement tiltott, amíg külön jóváhagyott gate nem engedi;
- Owner-döntést nem automatizálunk;
- public write, Memory, Swarm és global permission mutation alapból tiltott;
- shared run secret nem használható;
- titok nem kerülhet evidence-be, receiptbe, logba vagy publikus fixture-be;
- hash-gate eltérés esetén `STOP`;
- provider mismatch, token replay, lejárt permit vagy ismeretlen authority
  esetén fail closed;
- `unknown` outcome nem kezelhető automatikusan sikertelenként, és nem
  ismételhető vakon;
- külső tesztelő csak pontos verzióhoz és artifact-hashhez kötött csomagot
  kaphat.

Külön Owner-döntés nélkül továbbra is tilos:

- production vagy Gateway módosítása;
- provider write;
- ClawHub- vagy npm-publikáció;
- aktív install gate;
- issuer key custody kialakítása;
- public evidence endpoint vagy dataset publikálása;
- cross-Gateway authority vagy trust mesh bevezetése.

## 8. Végső stratégiai döntés

A versenytársak nem törlik el a NodeRooms lehetőségét. Viszont:

- az általános Passport-, permission- és receipt-történet már nem elegendő;
- az egyediséget nem névvel, hanem integrált bizonyítéklánccal kell
  létrehozni;
- a NodeRooms Alpha technikai alapja továbbvihető ebbe az irányba;
- a piaci védőárkot a verifier, a reprodukálható evidence, a külső tesztek és
  a cross-Gateway bizonyítás teremtheti meg;
- a következő időszak sikerkritériuma nem az ötlet, hanem az ellenőrizhető
  működés.

Irány: ne különálló generic tool-gate vagy receipt funkcióval versenyezzünk.
Építsük és bizonyítsuk a teljes Owner-bound, exact-artifact, outcome-linked
TrustBridge láncot.

## 9. Bemásolható rövid utasítás az Alpha2 fejlesztőnek

```text
Kezeld ezt a snapshotot a TrustBridge Alpha2 stratégiai kiegészítéseként.

Ne építs újabb generikus permission plugint vagy önálló receipt-rendszert.
A már elkészült NodeRooms Alpha contractokat és proofokat kösd össze ebbe a
láncba:

Verified Owner
→ Agent Passport
→ exact artifact/runtime fingerprint
→ Agent–Gateway binding
→ exact Owner-approved scoped permit
→ canonical intent és dispatch reservation
→ actual provider outcome
→ signed privacy-preserving receipt
→ idempotency/replay protection
→ portable cross-Gateway evidence.

Első cél a claw-runtime-evidence.v0.1 séma, az evidence adapter és a külső,
titokmentes verifier. Minden állítást jelölj implemented and locally tested,
contract-level, isolated provider proof, observe-only, external validation
pending, cross-Gateway proof pending vagy production enforcement disabled
státusszal.

Ne módosítsd a stabil 1.3.0 release-forrást vagy package identityt. Ne
engedélyezz production enforcementet. Ne automatizálj Owner-döntést. Hash
mismatch vagy authority-bizonytalanság esetén STOP.
```

## 10. Hatás a 005A–005G sorrendre

| Fázis | Stratégiai szerep | Jelenlegi állítás |
|---|---|---|
| 005A | Nyílt evidence-contract és public-safe tesztvektorok | `contract-level` |
| 005B | Exact artifact/runtime fingerprint engine | `external validation pending` |
| 005C | Authority–intent–outcome–receipt evidence adapter | `external validation pending` |
| 005D | Külső, titokmentes verifier | `external validation pending` |
| 005E | GitHub és messaging reprodukálható fixture/proof | `external validation pending` |
| 005F | `security.installPolicy` opt-in, kezdetben `observe-only` pilot | `external validation pending` |
| 005G | ClawHub `expected_checks` és external-evidence mapping | `external validation pending` |
| Későbbi proof | Cross-Gateway és több-Owner validáció | `cross-Gateway proof pending` |

Az evidence leíró bizonyíték, nem authority. A verifier ellenőriz, de nem
grantol jogosultságot. Egyetlen Alpha2-evidence sem minősíthet artifactot
abszolút biztonságosnak.
