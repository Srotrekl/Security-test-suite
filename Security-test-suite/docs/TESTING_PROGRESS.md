# Testing Progress — Co bylo otestováno

**Datum:** 2026-03-26
**Verze Juice Shop:** 19.2.1
**Tester:** Steve

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

### Manuálně:
- [ ] **IDOR basket** — přihlásit se jako User A, zkusit `/rest/basket/` jiného uživatele přes Console
- [ ] **Slabé heslo v UI** — zkusit registraci s heslem `123` v prohlížeči
- [ ] **Brute force v UI** — 10x špatné heslo, zobrazí se lockout?
- [ ] **Security headers** — F12 → Network → Response Headers zkontrolovat
- [ ] **Default credentials** — `jim@juice-sh.op` / `ncc-1701`

### Automaticky (nespuštěno):
- [ ] **UI testy** — `python -m pytest tests/ui/ -v` (Playwright)
  - DOM XSS v prohlížeči
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
