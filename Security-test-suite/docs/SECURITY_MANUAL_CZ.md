# Security testing — příručka pro začátečníky

---

## Co je security testing?

Normální testování ověřuje že aplikace dělá co má.
Security testing ověřuje že aplikace **nedělá co nemá** — tzn. že útočník nemůže získat přístup k datům, ovládnout aplikaci nebo poškodit ostatní uživatele.

---

## Úroveň 1 — Základy (začni tady)

### Co je zranitelnost?
Chyba v aplikaci kterou útočník může zneužít. Například:
- Přihlašovací formulář který přijme cokoliv
- Soubory přístupné bez přihlášení
- Chybová hláška která odhaluje příliš mnoho info

### Jak útočník přemýšlí?
Ptá se: *"Co se stane když zadám něco neočekávaného?"*
- Co když místo jména zadám `<script>`?
- Co když místo čísla zadám `' OR 1=1`?
- Co když změním číslo v URL z `1` na `2`?

### Kde testovat?
Nikdy netestuj na cizích aplikacích bez povolení — je to nelegální.
Testuj na:
- **OWASP Juice Shop** — záměrně zranitelná aplikace (používáme my)
- **DVWA** — další tréninková aplikace
- **Vlastní lokální prostředí**

---

## Úroveň 2 — OWASP Top 10

OWASP je organizace která každé 4 roky vydává seznam 10 nejčastějších zranitelností.
Každý security tester by měl znát tuto listinu nazpaměť.

### A01 — Broken Access Control (Špatná kontrola přístupu)
**Co to je:** Uživatel se dostane kam nemá.

**Příklady:**
- Změníš v URL `/basket/1` na `/basket/2` a vidíš košík cizího uživatele
- Přihlásíš se jako běžný uživatel ale dostaneš se na `/admin`
- Smažeš cizí objednávku

**Jak testovat:**
1. Přihlas se jako User A, zkopíruj URL nebo ID
2. Přihlas se jako User B, zkus přistoupit ke stejnému ID
3. Pokud vidíš data User A = ZRANITELNOST

---

### A02 — Cryptographic Failures (Špatné šifrování)
**Co to je:** Citlivá data nejsou chráněna nebo jsou špatně zašifrována.

**Příklady:**
- Hesla uložena jako plain text v databázi
- Citlivé soubory přístupné přes URL (`/ftp/`, `/backup/`)
- HTTP místo HTTPS
- Slabé šifrování (MD5, SHA1 pro hesla)

**Jak testovat:**
1. Zkus přistoupit na `/ftp/`, `/backup/`, `/.env`, `/config/`
2. Zkontroluj jestli web používá HTTPS
3. Prohlédni JS soubory — nejsou tam API klíče?

---

### A03 — Injection (Injekce)
**Co to je:** Útočník vloží škodlivý kód do vstupu aplikace.

#### SQL Injection
Útočník manipuluje s databázovým dotazem.

**Jak funguje:**
```
Normální dotaz:  SELECT * FROM users WHERE email='steve@test.com'
Po útoku:        SELECT * FROM users WHERE email='' OR 1=1--'
                                                  ↑ vždy true = vrátí všechny uživatele
```

**Jak testovat:**
- Do loginového pole zadej: `' OR 1=1--`
- Do vyhledávání zadej: `'` (jen apostrof) — zobrazí se chyba?
- Pokud se přihlásíš bez hesla = ZRANITELNOST

#### XSS (Cross-Site Scripting)
Útočník vloží JavaScript který se spustí v prohlížeči jiného uživatele.

**Typy XSS:**
| Typ | Popis | Příklad |
|---|---|---|
| Reflected | Payload je v URL, spustí se ihned | `?search=<script>alert(1)</script>` |
| Stored | Payload se uloží do DB, spustí se pro každého | Recenze produktu s `<script>` |
| DOM-based | Payload manipuluje s DOM bez serveru | `<iframe src="javascript:alert(1)">` |

**Jak testovat:**
- Do search baru zadej: `<script>alert(1)</script>`
- Pokud se zobrazí alert = ZRANITELNOST
- Zkus také: `<img src=x onerror=alert(1)>`

---

### A04 — Insecure Design (Špatný návrh)
**Co to je:** Bezpečnostní chyba je v samotném návrhu, ne v implementaci.

**Příklady:**
- Formulář validuje vstup jen v prohlížeči (JavaScript) — ale ne na serveru
- Password reset posílá heslo emailem místo reset linku
- Aplikace odhaluje jiné chybové zprávy pro existující vs. neexistující email

**Jak testovat:**
- Obejdi JS validaci přímým API voláním (curl, Postman, DevTools Console)
- Zkus password reset — co se stane?
- Zkus přihlásit s existujícím emailem + špatným heslem vs. neexistujícím emailem — jsou zprávy stejné?

---

### A05 — Security Misconfiguration (Špatná konfigurace)
**Co to je:** Server nebo aplikace jsou špatně nakonfigurované.

**Příklady:**
- Chybí security headers (CSP, HSTS, X-Frame-Options)
- Defaultní hesla nezměněna (`admin/admin`)
- Debug mód zapnutý v produkci
- `/metrics`, `/status`, `/health` přístupné bez autentizace
- Výpis adresářů povolen (`/ftp/` zobrazí seznam souborů)

**Jak testovat:**
- F12 → Network → klikni na request → Response Headers — co tam chybí?
- Zkus URL: `/metrics`, `/.env`, `/robots.txt`, `/sitemap.xml`
- Zkus defaultní credentials: `admin/admin`, `admin/password`

**Důležité security headers:**
| Header | Co dělá |
|---|---|
| `Content-Security-Policy` | Zabraňuje XSS |
| `X-Frame-Options` | Zabraňuje clickjackingu |
| `Strict-Transport-Security` | Vynucuje HTTPS |
| `X-Content-Type-Options` | Zabraňuje MIME sniffingu |

---

### A07 — Identification & Authentication Failures
**Co to je:** Slabá autentizace nebo správa sessions.

**Příklady:**
- Aplikace povolí heslo `123`
- Žádný lockout po 10 špatných pokusech (brute force možný)
- JWT token platí i po odhlášení
- Session cookie bez `HttpOnly` nebo `Secure` flagu

**Jak testovat:**
- Zkus registraci s heslem `123` nebo `a` — je to povoleno?
- Zkus 20x špatné heslo — zablokuje tě to?
- Po odhlášení zkus starý token — funguje?

---

## Úroveň 3 — Nástroje

### Pro manuální testování
| Nástroj | K čemu |
|---|---|
| **Browser DevTools (F12)** | Network, Console, Application, Headers |
| **Postman** | Posílání HTTP requestů, manipulace s tokeny |
| **Burp Suite** | Intercept proxy — zachytí a upraví každý request |

### Pro automatizované testování
| Nástroj | K čemu |
|---|---|
| **pytest + httpx** | API security testy (používáme my) |
| **Playwright** | UI security testy v prohlížeči |
| **OWASP ZAP** | Automatický DAST scan |

---

## Úroveň 4 — Pokročilé koncepty

Až zvládneš základy, tady jsou další témata:

| Téma | Popis |
|---|---|
| **JWT manipulation** | Padělání autentizačních tokenů |
| **IDOR** | Přístup k cizím datům přes ID v URL/body |
| **CSRF** | Útok přes odkaz v emailu — provede akci bez vědomí uživatele |
| **XXE** | Útok přes XML upload — čte soubory ze serveru |
| **SSRF** | Server jako proxy pro útok na interní síť |
| **Path traversal** | `../../etc/passwd` — čtení libovolných souborů |
| **Insecure deserialization** | Útok přes manipulaci serializovaných objektů |

---

## Jak psát bug report

Každou nalezenou zranitelnost zdokumentuj takto:

```
Název:       DOM XSS ve vyhledávání
Závažnost:   High
OWASP:       A03 Injection
URL:         http://app.com/search

Kroky:
1. Jdi na stránku vyhledávání
2. Zadej: <iframe src="javascript:alert('xss')">
3. Zmáčkni Enter

Očekávaný výsledek:  Payload je enkódován, žádný JavaScript nespuštěn
Skutečný výsledek:   JavaScript byl spuštěn v prohlížeči

Dopad:
Útočník může ukrást session cookie nebo přesměrovat uživatele na phishing stránku.
```

---

## Shrnutí — kde začít

1. Otevři Juice Shop (`http://localhost:3000`)
2. Zkus manuálně: SQL injection na login, XSS ve search, `/ftp/` URL
3. Podívej se na security headers (F12 → Network → Response Headers)
4. Naučíš se Postman pro API testování
5. Přidej automatizované testy do pytest

*Bezpečnostní testování je o zvědavosti — vždy se ptej "co se stane když...?"*
