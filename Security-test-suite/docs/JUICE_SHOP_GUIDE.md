# Juice Shop — Praktický průvodce

## Co je Juice Shop

Záměrně zranitelný e-shop vytvořený OWASP organizací. Vypadá jako normální web,
ale obsahuje desítky záměrných bezpečnostních děr. Slouží k bezpečnému tréninku
security testování — nikdy neškodit reálným systémům.

**Technologie za appkou:** Node.js + Angular + SQLite
**Naše role:** Testujeme ji jako černou skříňku — nezajímá nás jak je napsaná

---

## Spuštění

```powershell
# Terminal 1 — Juice Shop (nechej běžet)
cd C:\Users\steve\Desktop\Projects\juice-shop_19.2.1
node build/app.js

# Počkej na: "Server listening on port 3000"
```

Otevři v prohlížeči: **http://localhost:3000**

---

## Co aplikace umí (jako normální uživatel)

| Funkce | URL |
|--------|-----|
| Registrace / Login | `/#/register`, `/#/login` |
| Vyhledávání produktů | `/#/search` |
| Košík | `/#/basket` |
| Profil uživatele | `/#/profile` |
| Recenze produktů | klikni na produkt |
| Admin panel | `/#/administration` (jen admin) |

**Default admin účet:**
- Email: `admin@juice-sh.op`
- Heslo: `admin123`

---

## Jak interpretovat výsledky testů

```
PASSED = aplikace se správně brání útoku
FAILED = nalezená zranitelnost (test splnil účel!)
```

Oba výsledky jsou správné. FAIL neznamená chybu v testu — znamená díru v appce.

---

## Spuštění testů

```powershell
# Terminal 2 — testy (Juice Shop musí běžet!)
cd C:\Users\steve\Desktop\Projects\Security-test-suite

# Všechny API testy
python -m pytest tests/api/ -v

# Všechny UI testy (Playwright)
python -m pytest tests/ui/ -v

# Podle kategorie zranitelnosti
python -m pytest -m sqli -v        # SQL Injection
python -m pytest -m xss -v         # Cross-site scripting
python -m pytest -m auth -v        # Autentizace
python -m pytest -m idor -v        # Broken access control
python -m pytest -m headers -v     # Security headers
python -m pytest -m critical -v    # Jen kritické nálezy

# S HTML reportem
python -m pytest tests/api/ --html=reports/report.html --self-contained-html
```

---

## Přehled testů a co hledají

### API testy (`tests/api/`)

| Soubor | OWASP | Co testuje |
|--------|-------|-----------|
| `test_sql_injection.py` | A03 | Pošle `' OR 1=1--` do login/search — přihlásí se bez hesla? |
| `test_xss.py` | A03 | Vloží `<script>alert('xss')` do recenze/search — vrátí se needitovaný? |
| `test_authentication.py` | A07 | Slabá hesla, brute force, JWT padělání, session po logout |
| `test_idor.py` | A01 | Přistoupí na košík/profil jiného uživatele změnou ID v URL |
| `test_rate_limiting.py` | A07 | Pošle 50 loginů za sebou — dostane 429? |
| `test_security_headers.py` | A05 | Kontroluje X-Frame-Options, CSP, HSTS v HTTP odpovědích |
| `test_cors.py` | A05 | Pošle Origin: evil.com — vrátí server tento origin? |

### UI testy (`tests/ui/`) — Playwright Chromium

| Soubor | Co testuje |
|--------|-----------|
| `test_dom_xss.py` | Vloží XSS přes search bar v prohlížeči — spustí se JS? |
| `test_clickjacking.py` | Zkusí embedovat stránku do iframe — povedlo se? |
| `test_login_security.py` | Formulář: maskování hesla, user enumeration, CSRF |
| `test_sensitive_data_exposure.py` | HTML komentáře, secrets v JS, console.log, autocomplete |

---

## Výsledky z reálného spuštění

Z našeho testu na Juice Shop v19.2.1:

**Nalezené zranitelnosti (FAIL):**
- Přijímá slabá hesla: `123`, `password`, `abc`
- Žádný brute force lockout (20 pokusů povoleno)
- Expired JWT token přijat (vrátí 200 místo 401)
- Token platný i po logout
- Default credentials fungují (`admin123`, `ncc-1701`)
- IDOR: přístup k košíku jiného uživatele
- IDOR: přístup k profilu admina přes `/api/Users/1`
- Žádný rate limiting (login, registrace, reset hesla, search)
- Chybí CSP header na všech endpointech
- Chybí HSTS header
- CORS: DELETE povoleno přes preflight

**Fungující obrany (PASS):**
- SQL Injection — všechny payloady zablokované
- XSS v search — výstup správně enkódovaný
- CORS — arbitrary origins odmítnuty
- X-Content-Type-Options: nosniff přítomen
- X-Frame-Options přítomen
- JWT none algorithm odmítnut
- JWT tampered role odmítnut

---

## Klíčový rozdíl od funkčního testování

| Funkční test | Security test |
|-------------|---------------|
| Testuješ co appka *má* dělat | Testuješ co appka *nemá* dělat |
| Vstup: validní data | Vstup: záměrně špatná/škodlivá data |
| FAIL = bug | FAIL = nalezená zranitelnost |
| Píše vývojář | Píše QA/security tester |
