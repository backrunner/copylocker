---
doc: eula-clause
version: 0.1.0
status: draft
language: de
master: ../eula-clause.md (en, v0.1.0)
data_source: data-inventory.md v0.1.0 (verified against code 2026-08-08)
---

# EULA-Klauseln — Lizenzprüfung & Telemetrie (de)

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
> (Maßgeblich ist die englische Master-Version `../eula-clause.md`.)

**Status: ENTWURF — muss vor Aufnahme in eine EULA von qualifiziertem Rechtsbeistand
geprüft werden.**

---

## Klausel {{CLAUSE_1}} — Lizenzprüfung

1. Die Software enthält eine Lizenzprüfungskomponente, die regelmäßig den Lizenzdienst
   von {{VENDOR_NAME}} kontaktiert, um zu bestätigen, dass Ihre Kopie ordnungsgemäß
   lizenziert ist und die Anzahl der genutzten Geräte die Plätze (Seats) Ihrer Lizenz
   nicht überschreitet.
2. Zu diesem Zweck überträgt die Software: eine Lizenzkennung; eine vom Server
   zugewiesene zufällige Gerätekennung; einen irreversiblen kryptografischen Hash
   (Fingerabdruck), der aus Hardwareattributen Ihres Geräts abgeleitet wird;
   öffentliche Geräteschlüssel; Softwareversion, Betriebssystem und Architektur;
   die verwendete Aktivierungsmethode; sowie einen am Netzwerkrand abgeleiteten
   Ländercode. Ihre IP-Adresse wird nicht gespeichert. Die vollständige, maßgebliche
   Liste der übertragenen Felder ist in unserer Datenschutzerklärung veröffentlicht
   ({{PRIVACY_POLICY_URL}}).
3. Die Lizenzprüfung ist Voraussetzung für die Nutzung der Software und kann nicht
   deaktiviert werden. Schlägt die Prüfung fehl, kann die Software ihre Funktionalität
   einschränken oder den Betrieb einstellen, wie in {{GRACE_POLICY_DOC}} beschrieben.
4. Der von Ihnen eingegebene Lizenzschlüssel wird vom Lizenzdienst niemals gespeichert;
   es wird nur ein keyed Hash davon aufbewahrt.

## Klausel {{CLAUSE_2}} — Optionale Nutzungsstatistiken

1. Wenn Sie ausdrücklich zustimmen, kann die Software zusätzlich voraggregierte
   Nutzungsstatistiken übermitteln (Anzahl der Sitzungen, ein grobes Histogramm der
   Sitzungslängen, Nutzungszähler für Funktionen, Anzahl der Nutzungstage pro Zeitraum).
   Die Berichte enthalten keine Inhalte, keine Dateinamen, keine Zeitstempel einzelner
   Aktionen und keinen genauen Standort.
2. Sie können die Einwilligung jederzeit in den Einstellungen der Software mit Wirkung
   für künftige Berichte widerrufen. Ablehnung oder Widerruf verringern keine
   Funktionalität der Software.

## Klausel {{CLAUSE_3}} — Nutzungsbeschränkungen

Sie dürfen nicht: (a) die Lizenzprüfungskomponente umgehen, deaktivieren oder
manipulieren; (b) die Software auf mehr Geräten nutzen, als Ihre Lizenz erlaubt;
(c) nutzerbezogene Wasserzeichen an geschützten Inhalten entfernen oder verändern; oder
(d) die Lizenzschnittstellen der Software nutzen, um den Lizenzdienst zu sondieren,
zu belasten oder anzugreifen. [[LEGAL REVIEW: mit zwingendem deutschen/EU-Recht
abgleichen — insbesondere §§ 69d, 69e UrhG (Sicherungskopie, Interoperabilität) und
AGB-Kontrolle nach §§ 305 ff. BGB schränken vertragliche Verbotsklauseln ein.]]

## Klausel {{CLAUSE_4}} — Ehrliche Grenzen des Schutzes

Der Kopierschutz der Software ist so konzipiert, dass unbefugte Nutzung **aufwendig und
nicht wiederverwendbar**, nicht jedoch unmöglich wird. Unter anderem kann ein Angreifer
mit vollständiger physischer Kontrolle über ein Gerät letztlich alles extrahieren, was
dieses Gerät entschlüsseln kann, und der Schutz in Webbrowser-Umgebungen ist grundsätzlich
schwächer als in nativen Anwendungen. Nichts in dieser Vereinbarung garantiert, dass
unbefugtes Kopieren unmöglich ist. (Diese Klausel spiegelt die öffentliche
Restrisiko-Erklärung des Projekts; mit `SECURITY.md` konsistent halten.)

## Klausel {{CLAUSE_5}} — Durchsetzung

Stellt der Lizenzdienst Missbrauchsindikatoren fest (z. B. Aktivierung auf einer
übermäßigen Anzahl unterschiedlicher Geräte), kann {{VENDOR_NAME}} die betroffene Lizenz
sperren oder widerrufen{{HUMAN_REVIEW_WORDING}}. [[LEGAL REVIEW: bei automatisierter
Durchsetzung Art. 22 DSGVO (automatisierte Einzelentscheidung) prüfen und hier eine
menschliche Überprüfung zusichern.]]

---

## Platzhalter

`{{CLAUSE_1}}`…`{{CLAUSE_5}}`, `{{VENDOR_NAME}}`, `{{PRIVACY_POLICY_URL}}`,
`{{GRACE_POLICY_DOC}}`, `{{HUMAN_REVIEW_WORDING}}`.

## Prüfpunkte

Alle `[[LEGAL REVIEW]]`-Punkte der englischen Master-Version gelten; zusätzlich deutsche
Prüfung nach AGB-Recht (§§ 305 ff. BGB) und UrhG.
