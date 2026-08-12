---
doc: consent-ui-copy
version: 0.1.0
status: draft
language: de
master: ../consent-ui-copy.md (en, v0.1.0)
data_source: data-inventory.md v0.1.0 (verified against code 2026-08-08)
---

# Einwilligungs-Dialog — Vorlage für Nutzungsstatistik-Opt-in (de)

> ⚠️ **Haftungsausschluss (muss wörtlich oben in jeder Vorlage stehen)**
>
> Alle Dokumente in diesem Verzeichnis sind **technische Vorlagen des Engineering-Teams**,
> um dem Vendor die Erstellung von Compliance-Dokumenten zu erleichtern.
> Sie sind **keine Rechtsberatung**, begründen kein Anwalt-Mandant-Verhältnis und
> garantieren keine Compliance in irgendeiner Rechtsordnung.
> Der Vendor **muss** sie vor Verwendung von qualifiziertem Rechtsbeistand prüfen und an
> das eigene Geschäft, die eigenen Datenflüsse und das anwendbare Recht anpassen lassen.
> Das CopyLocker-Projekt übernimmt keine Haftung für rechtliche Folgen aus der Verwendung
> dieser Vorlagen.

> 🌐 **Maschinell unterstützter Entwurf — muss vor Verwendung von einem professionellen
> juristischen Übersetzer geprüft werden.**
> (Maßgeblich ist die englische Master-Version `../consent-ui-copy.md`.)

**Status: ENTWURF — muss vor Veröffentlichung von qualifiziertem Rechtsbeistand geprüft
werden.** Mechanik und Platzhalter siehe englische Master-Version.

---

## 1. Erststart-Dialog

**Titel:** Helfen Sie, {{PRODUCT_NAME}} zu verbessern?

**Text:**

> {{PRODUCT_NAME}} kann uns anonyme Nutzungsstatistiken senden, die uns helfen zu
> entscheiden, was wir verbessern.
>
> **Was gesendet wird, wenn Sie zustimmen:**
>
> - wie oft Sie die App pro Berichtszeitraum genutzt haben;
> - ein grobes Histogramm der Sitzungslängen (vier Bereiche — niemals exakte Zeiten);
> - wie oft bestimmte Funktionen genutzt wurden (nur Funktionsnamen);
> - an wie vielen Tagen pro Monat die App genutzt wurde;
> - die Version dieses Hinweises, der Sie zugestimmt haben.
>
> **Was niemals gesendet wird:** alles, was Sie eingeben, Dateinamen oder Pfade,
> Zwischenablage- oder Bildschirminhalte, Kontakte, genauer Standort, Browserverlauf
> sowie Reihenfolge und Zeitpunkt einzelner Aktionen.
>
> Statistiken werden ausschließlich an unsere eigenen Server gesendet (Infrastruktur:
> Cloudflare); kein Analyse- oder Werbedienst eines Dritten erhält sie.
>
> Eine Ablehnung ändert nichts an der Funktionsweise der App. Sie können Ihre Wahl
> jederzeit unter **Einstellungen → {{SETTINGS_ENTRY}}** ändern; die Änderung gilt ab
> dem nächsten Bericht.
>
> *Die Lizenzprüfung läuft unabhängig von dieser Wahl und kann nicht abgeschaltet werden
> — sie ist erforderlich, um Ihre lizenzierte Kopie zu betreiben. Details:
> {{PRIVACY_POLICY_URL}}.*

**Schaltflächen:** `[Zustimmen]` `[Ablehnen]` — gleiche visuelle Gewichtung.

**Link:** „Vollständige Datenliste" → Abschnitt der Datenschutzerklärung des Vendors.

## 2. Einstellungs-Schalter (permanenter Widerrufseinstieg)

> **Nutzungsstatistiken** `[Schalter, standardmäßig aus]`
> Teilen Sie anonyme Nutzungszähler, um {{PRODUCT_NAME}} zu verbessern. Es werden niemals
> Inhalte, Dateien oder genaues Verhalten gesendet. Das Ausschalten stoppt den nächsten
> Bericht; bereits gesendete Zähler werden auf Anfrage gelöscht ({{DSR_CONTACT}}).
> Details: {{PRIVACY_POLICY_URL}}.

## 3. Widerrufs-Bestätigung (optionaler Mikrotext)

> Nutzungsstatistiken sind aus. Es werden keine weiteren Berichte gesendet. Dies
> beeinträchtigt keine Funktion von {{PRODUCT_NAME}}.

## 4. Platzhalter

`{{PRODUCT_NAME}}`, `{{SETTINGS_ENTRY}}`, `{{PRIVACY_POLICY_URL}}`, `{{DSR_CONTACT}}`.

## 5. Rechtliche Prüfpunkte

Alle `[[LEGAL REVIEW]]`-Punkte der englischen Master-Version gelten; zusätzlich:

- [[LEGAL REVIEW: deutsche/EU-spezifische Prüfung — Einwilligungswirksamkeit nach TTDSG
  § 25 (Endeinrichtungszugriff) und DSGVO Art. 7; Formulierung „anonym" ggf. durch
  „ohne Personenbezug über die Lizenzprüfung hinaus" ersetzen.]]
