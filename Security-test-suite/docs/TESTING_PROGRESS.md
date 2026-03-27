# Testing Progress — Co bylo otestováno

**Datum:** 2026-03-27
**Verze Juice Shop:** 19.2.1
**Tester:** Steve
**Celkem challenges:** 111 | **Vyreseno:** 12 | **Zbývá:** 99

---

## OTESTOVÁNO — Manuálně (2026-03-27)

### Session 2 — 5 nových challenges

### 6. DOM XSS
- **Payload:** `<iframe src="javascript:alert('xss')">`  do search baru
- **Výsledek:** ZRANITELNOST — JavaScript spuštěn v prohlížeči
- **OWASP:** A03 Injection / XSS
- **Dopad:** Útočník může ukrást session cookie nebo přesměrovat uživatele
- **Challenge:** DOM XSS (D1) ✅

### 7. Confidential Document
- **URL:** `http://localhost:3000/ftp/`
- **Výsledek:** ZRANITELNOST — FTP adresář veřejně přístupný bez autentizace, stažen soubor
- **OWASP:** A02 Cryptographic Failures / Sensitive Data Exposure
- **Dopad:** Interní dokumenty, zálohy, API klíče přístupné komukoliv
- **Challenge:** Confidential Document (D1) ✅

### 8. Zero Stars
- **Metoda:** POST `/api/Feedbacks` s `rating: 0` přes DevTools Console (obejití UI validace)
- **Výsledek:** ZRANITELNOST — server přijal rating=0, chybí server-side validace
- **OWASP:** A04 Insecure Design / Improper Input Validation
- **Dopad:** Útočník obejde jakoukoliv client-side validaci přímým API voláním
- **Challenge:** Zero Stars (D1) ✅

### 9. Exposed Metrics
- **URL:** `http://localhost:3000/metrics`
- **Výsledek:** ZRANITELNOST — Prometheus metriky přístupné bez autentizace
- **Nalezeno:** CPU usage, memory, startup časy, file upload počty, technologie (Node.js)
- **OWASP:** A05 Security Misconfiguration / Observability Failures
- **Dopad:** Útočník zjistí technologický stack a interní stav aplikace
- **Challenge:** Exposed Metrics (D1) ✅

### 10. Admin Section
- **Metoda:** SQL injection na login (`' OR true--`) → přístup jako admin → `/#/administration`
- **Výsledek:** ZRANITELNOST — admin panel přístupný po SQL injection bypassu
- **OWASP:** A01 Broken Access Control + A03 Injection
- **Dopad:** Přístup ke všem uživatelům, objednávkám, možnost mazat reviews
- **Challenge:** Admin Section (D2) ✅

---

## OTESTOVÁNO — Manuálně

### 1. SQL Injection — Login bypass
- **Payload:** `' OR 1=1--` do pole Email
- **Výsledek:** ZRANITELNOST — přihlásilo jako admin bez hesla
- **OWASP:** A03 Injection
- **Automatický test:** `test_sql_injection_login_bypass` ✅

### 2. XSS — Search bar
- **Payload:** `<script>alert('XSS')</script>`
- **Výsledek:** CHRÁNĚNO — payload enkódován, žádný alert
- **OWASP:** A03 Injection
- **Automatický test:** `test_xss_reflected_in_search` ✅

### 3. XSS — Recenze produktu (Stored XSS)
- **Payload:** `<iframe src="javascript:alert('XSS')">`
- **Výsledek:** CHRÁNĚNO — zobrazilo se jako text
- **OWASP:** A03 Injection
- **Automatický test:** `test_xss_stored_in_product_review` ✅

### 4. Admin panel — přístup jako admin
- **URL:** `http://localhost:3000/#/administration`
- **Výsledek:** ZRANITELNOST — viditelní všichni uživatelé + možnost mazat
- **OWASP:** A01 Broken Access Control
- **Poznámka:** URL není v menu, ale pokud ji znáš — dostaneš se tam

### 5. Admin panel — přístup bez loginu
- **URL:** `http://localhost:3000/#/administration` po odhlášení
- **Výsledek:** CHRÁNĚNO — přesměrování na hlavní stránku

### 6. SQL Injection — potvrzení
- **Výsledek:** Juice Shop zobrazil zelené "You successfully solved a challenge: Login Admin"

---

## OTESTOVÁNO — Automaticky (pytest)

Spuštěno: `python -m pytest tests/api/ -v`
Výsledek: **49 passed / 32 failed**

### Nalezené zranitelnosti (FAILED):
- Slabá hesla přijata: `123`, `password`, `abc`, `1234`, `a`
- Brute force — žádný lockout po 20 pokusech
- Expired JWT token přijat (200 místo 401)
- Token platný i po logout
- Default credentials fungují: `admin@juice-sh.op/admin123`, `jim@juice-sh.op/ncc-1701`
- IDOR — přístup k košíku jiného uživatele
- IDOR — přístup k profilu admin uživatele přes `/api/Users/1`
- Žádný rate limiting na login, registraci, reset hesla, search
- Chybí CSP header na všech endpointech
- Chybí HSTS header
- CORS — DELETE metoda povolena přes preflight

### Fungující obrany (PASSED):
- SQL Injection — všechny payloady zablokované v API
- XSS v search — výstup enkódován
- CORS — arbitrary origins odmítnuty
- X-Content-Type-Options: nosniff přítomen
- X-Frame-Options přítomen
- JWT none algorithm odmítnut
- JWT tampered role odmítnut

---

## ZBÝVÁ OTESTOVAT

### Faze 1 — Lehke (D1-D2) — zacneme tady
| Challenge | Co udelat | Kde |
|---|---|---|
| DOM XSS | Do search zadat: `<iframe src="javascript:alert('xss')">` | localhost:3000 search bar |
| Zero Stars | Odeslat hodnoceni produktu s 0 hvezdami | localhost:3000 produkt → Review |
| Reflected XSS | `<iframe src="javascript:alert('xss')">` v URL parametru | localhost:3000/#/search?q=... |
| Confidential Document | Pristup na `http://localhost:3000/ftp/` | prohlizec |
| Repetitive Registration | Registrovat se 2x se stejnym emailem | localhost:3000/#/register |
| Outdated Allowlist | `http://localhost:3000/redirect?to=https://github.com` | prohlizec |
| Exposed Metrics | Pristup na `http://localhost:3000/metrics` | prohlizec |
| Bonus Payload | `<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="javascript:alert('xss')">` | search |
| Bully Chatbot | Otevrit chatbota a tlacit ho az rekne kupon | localhost:3000 chatbot |
| Missing Encoding | Hledat foto s `#` v nazvu | prohlizec |

### Faze 2 — Stredni (D3) — dalsi sprint
| Challenge | Co udelat |
|---|---|
| Admin Registration | POST /api/Users s `"role":"admin"` v body |
| CAPTCHA Bypass | Odeslat feedback 2x se stejnym CAPTCHA resenim |
| Forged Feedback | POST /api/Feedbacks s cizim UserId |
| Forged Review | PUT na recenzi jineho uzivatele |
| Database Schema | SQLi: `')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--` |
| Login Bender | SQLi: `bender@juice-sh.op'--` |
| Upload Size | Nahrat soubor vetsi nez 100kb |
| Upload Type | Nahrat soubor s priponou `.exe` nebo `.xml` |
| XXE Data Access | Upload XML s `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` |
| CSRF | Zmenit email uzivatele pres externi stranku |

### Automaticky (nespuštěno):
- [ ] **UI testy** — `python -m pytest tests/ui/ -v` (Playwright)
  - DOM XSS v prohlizeci
  - Clickjacking test
  - Login form security
  - Sensitive data exposure

### Pokročilé (volitelné):
- [ ] **JWT manipulace** — ručně padělaný token v Postmanu
- [ ] **Path traversal** — `../../../../etc/passwd` v URL
- [ ] **ZAP baseline scan** — automatický DAST scan (potřeba Docker)

---

## Jak spustit zbývající testy

```powershell
# UI testy (Playwright)
cd C:\Users\steve\Desktop\Projects\Security-test-suite
python -m pytest tests/ui/ -v

# Konkrétní kategorie
python -m pytest -m sqli -v
python -m pytest -m auth -v
python -m pytest -m idor -v

# HTML report
python -m pytest tests/api/ --html=reports/report.html --self-contained-html
```

---

## Poznámky

- Juice Shop v19 má XSS v search opravený (starší verze byly zranitelné)
- IDOR přes URL v prohlížeči vyžaduje token — testovat přes Console nebo pytest
- Databáze se resetuje při restartu Juice Shopu
- Port 3000 obsazený = `taskkill /PID <číslo> /F` pak restart
