# Archydes-Archivformat – Spezifikation

Version 1.1 · Stand: 26. November 2026 · © 2026 SOLIT SRL

**Jeder darf dieses Format ohne Lizenzgebühren lesen und schreiben und eigene Implementierungen erstellen.**

Diese Spezifikation beschreibt die Formatversionen 1.0 (unverschlüsselt) und 1.1 (verschlüsselt).

Diese Spezifikation steht unter der Lizenz [Creative Commons Namensnennung 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/deed.de). Die Referenzimplementierung zum Lesen (Bibliotheken und Kommandozeilen-Tool `archydes`) steht unter `MIT OR Apache-2.0`.

## A1. Ziel

Das Archydes-Format ist ein Archivformat, das drei Eigenschaften vereint, die es so in keinem gängigen Format gibt:

1. **Deduplizierung:** Gleiche Daten werden nur einmal gespeichert, auch über Dateigrenzen und Versionen hinweg.
2. **Nachpacken:** Bereits komprimierte Dateien (JPEG, JPEGs in PDF-Scans, Deflate-Daten in PDF/DOCX/XLSX/ZIP) werden verlustfrei weiter verkleinert und beim Entpacken **bitgenau** wiederhergestellt.
3. **Langzeitsicherheit:** Prüfsummen überall, optionale Wiederherstellungsdaten (Reed-Solomon) zum Reparieren beschädigter Archive, offene Spezifikation, versionierte Struktur.

Außerdem sind **mehrere Versionen** in einem Archiv (Snapshots, A10) und **Verschlüsselung** (A11) Teil des Formats.

## A2. Designprinzipien

1. **Bitgenauigkeit ist heilig.** Jede entpackte Datei muss Byte für Byte dem Original entsprechen. Der Packer prüft jede Transformation vor dem Schreiben, indem er sie zurückrechnet. Schlägt die Prüfung fehl, wird die Datei unverändert (RAW) gespeichert.
2. **Erweiterbar über Kennungen.** Jeder Codec und jede Transformation hat eine numerische Kennung. Neue Verfahren bekommen neue Kennungen, alte bleiben gültig. Ein Decoder, der eine Kennung nicht kennt, meldet einen klaren Fehler und rät nicht.
3. **Alles ist geprüft.** Header, Segmente, Packs und Originaldateien haben Prüfsummen bzw. Hashes.
4. **Robust gegen Teilschäden.** Ein beschädigter Bereich soll nur die betroffenen Dateien unlesbar machen, nicht das ganze Archiv. Mit Wiederherstellungsdaten sollen Schäden reparierbar sein.
5. **Nur anhängen.** Neue Versionen werden ans Ende angehängt, bestehende Daten werden nie überschrieben. Ein Absturz beim Schreiben darf die bisherige Version nicht zerstören.
6. **Offen und langlebig.** Die Spezifikation ist veröffentlicht. Das Kommandozeilen-Tool `archydes` zum Auflisten, Entpacken, Prüfen und Reparieren ist Open Source (`MIT OR Apache-2.0`), damit das Entpacken nie von einer kommerziellen Software abhängt. Es werden nur gut spezifizierte Grundbausteine verwendet (CBOR, BLAKE3, zstd, LZMA2, ISO/IEC 18181).
7. **Parallelisierbar.** Packs werden unabhängig voneinander komprimiert und dekomprimiert, damit alle CPU-Kerne genutzt werden.

## A3. Begriffe

| Begriff | Bedeutung |
|---|---|
| **Segment** | Grundeinheit der Datei: Kopf plus Nutzdaten (Pack, Index, Wiederherstellungsdaten …) |
| **Chunk** | Datenblock nach dem Zerlegen eines Streams (inhaltsbasiert, ca. 256 KiB). Kennung: BLAKE3-256 des Inhalts |
| **Pack** | Gruppe von Chunks, die gemeinsam (solid) mit einem Codec komprimiert sind; Ziel 16 MiB unkomprimiert |
| **Stream** | Logische Bytefolge = geordnete Liste von Chunks |
| **Rezept** | Anleitung, wie aus Streams die Originaldatei entsteht (Folge von Teilen mit Transformationen) |
| **Transformation** | Umkehrbare Umwandlung, z. B. JPEG XL → JPEG, entpackte Daten → Original-Deflate-Strom |
| **Eintrag** | Datei, Ordner, Symlink oder Hardlink mit Metadaten und Rezept |
| **Snapshot** | Stand eines Ordners zu einem Zeitpunkt = Liste von Einträgen |
| **Index** | Inhaltsverzeichnis: Pack-Tabelle, Chunk-Tabelle, alle Snapshots |
| **Generation** | Zähler, der bei jedem Anhängen steigt |

## A4. Grundregeln der Kodierung

- Alle Ganzzahlen in festen Strukturen: **Little Endian**.
- Prüfsumme für Köpfe: **CRC32C** (Castagnoli).
- Hash für Inhalte: **BLAKE3**. Volle Länge (32 Byte) für Chunk-IDs und Dateihashes, die ersten 16 Byte („BLAKE3-128“) für Segment-Nutzdaten.
- Strukturierte Daten (Index, Metadaten): **CBOR** (RFC 8949), deterministische Kodierung (RFC 8949 §4.2.1). Verwendet wird nur eine Teilmenge: vorzeichenlose und negative Ganzzahlen, Byte- und Textstrings, Arrays, Maps, `false`, `true`, `null`, jeweils mit fester Länge. Keine Tags, keine Gleitkommazahlen, keine unbestimmten Längen. Ein Decoder darf andere CBOR-Elemente ablehnen. Unbekannte Schlüssel in Maps überspringt er (Vorwärtskompatibilität).
- Zeitstempel: Nanosekunden seit 1970-01-01 UTC, vorzeichenbehaftet 64 Bit.
- Dateipfade: Bytes, so wie das Dateisystem sie liefert (auf macOS meist NFD), Trennzeichen `/`, immer relativ. Zusätzlich wird die NFC-Form für Anzeige und Vergleich gespeichert.

## A5. Dateiaufbau

```
+--------------------------------------------------+
| Header (64 Byte, fest)                           |
+--------------------------------------------------+
| Segment FORMAT_INFO (Klartext-Beschreibung)      |
| Segment KEY_INFO         (nur verschlüsselt, A11)|
+--------------------------------------------------+
| Segment PACK  |  Segment PACK  |  …              |
+--------------------------------------------------+
| Segment KEY_INFO         (Kopie, verschlüsselt)  |
| Segment INDEX            (Generation n)          |
| Segment INDEX_COPY       (identisch)             |
+--------------------------------------------------+
| Segment RECOVERY         (optional)              |
+--------------------------------------------------+
| Footer (64 Byte, fest)                           |
+--------------------------------------------------+
   … beim Anhängen einer neuen Version folgen weitere
     PACK-Segmente, (nur verschlüsselt) eine Kopie von
     KEY_INFO, ein neuer INDEX, INDEX_COPY, optional
     RECOVERY und ein Footer. Der letzte gültige
     Footer gilt.
```

### A5.1 Header (Offset 0, 64 Byte)

| Offset | Größe | Feld | Inhalt |
|---|---|---|---|
| 0 | 8 | magic | `89 41 52 43 48 0D 0A 1A` (`\x89ARCH\r\n\x1A`, nach PNG-Vorbild: erkennt Text-Modus-Übertragungsfehler) |
| 8 | 2 | format_major | 1 |
| 10 | 2 | format_minor | 0; 1 bei verschlüsselten Archiven (A11) |
| 12 | 4 | flags | Zustand **bei der Erstellung**, nur informativ; Bits siehe unten |
| 16 | 16 | archive_uuid | zufällige UUID (v4) |
| 32 | 8 | created_ns | Erstellzeit |
| 40 | 20 | reserved | 0 |
| 60 | 4 | crc32c | über Byte 0–59 |

Archiv-Flags (im Header und im Footer):

| Bit | Name | Gesetzt, wenn |
|---|---|---|
| 0 | `ENCRYPTED` | das Archiv verschlüsselt ist (A11) |
| 1 | `RECOVERY` | Wiederherstellungsdaten vorhanden sind: `recovery_offset` im Footer ist nicht 0 (A9) |
| 2 | `MULTIPLE_SNAPSHOTS` | der Index mehr als einen Snapshot enthält |
| 3–31 | – | reserviert, 0 |

Der Header wird nach dem Erstellen nie mehr geschrieben (Nur anhängen). Maßgeblich für den aktuellen Zustand sind die Flags im **letzten gültigen Footer** (A5.4). Ein Decoder darf aus den Header-Flags nichts über den aktuellen Zustand schließen. Ausnahme: Bit 0 (verschlüsselt) kann sich nicht ändern, Header und Footer müssen darin übereinstimmen, sonst gilt das Archiv als beschädigt.

**Versionsregel:** Ein Decoder lehnt ein höheres `format_major` ab. Ein höheres `format_minor` darf er lesen. Unbekannte Segmenttypen (A5.2) mit gesetztem Flag `CRITICAL` bedeuten, dass das Archiv einen neueren Decoder braucht: Der Decoder darf sein Ergebnis nicht als vollständig ausgeben (`verify` meldet ein solches Segment als Problem). Unbekannte Segmenttypen ohne das Flag überspringt er.

### A5.2 Segmentkopf (40 Byte)

| Offset | Größe | Feld | Inhalt |
|---|---|---|---|
| 0 | 4 | magic | `AHSG` |
| 4 | 2 | type | siehe Tabelle |
| 6 | 2 | flags | Bit 0 `CRITICAL`, Bit 1 `ENCRYPTED`, Bits 2–15 reserviert (0) |
| 8 | 8 | payload_len | Länge der Nutzdaten in Byte |
| 16 | 16 | payload_hash | BLAKE3-128 der Nutzdaten (wie gespeichert) |
| 32 | 4 | reserved | 0 |
| 36 | 4 | crc32c | über Byte 0–35 |

| Typ | Name | kritisch | Inhalt |
|---|---|---|---|
| 0x0001 | PACK | ja | komprimierte Chunks |
| 0x0002 | INDEX | ja | Inhaltsverzeichnis (CBOR, zstd-komprimiert) |
| 0x0003 | INDEX_COPY | nein | identische Kopie des INDEX |
| 0x0004 | RECOVERY | nein | Reed-Solomon-Daten |
| 0x0005 | FORMAT_INFO | nein | UTF-8-Klartext: Formatname, Version, URL der Spezifikation, Hinweis auf das freie Entpack-Tool `archydes` |
| 0x0006 | PLAIN_TOC | nein | optional, nur unverschlüsselt: Dateiliste als UTF-8-Klartext (für Menschen, ohne Software lesbar) |
| 0x0007 | KEY_INFO | ja | nur bei Verschlüsselung (A11): Argon2-Parameter, Salt, eingepackter Datenschlüssel |
| 0x0000, 0x0008–0x7FFF | – | – | reserviert für künftige Versionen |
| 0x8000–0xFFFF | – | nein | frei für Experimente, von Decodern zu ignorieren |

`CRITICAL` bedeutet, dass ein Decoder das Archiv ohne Verständnis des Segments nicht richtig lesen kann. Ein Packer setzt es genau wie in der Spalte „Kritisch“. Für die Typen dieser Tabelle entscheidet die Tabelle: Ein Decoder beachtet das Flag nicht und behandelt das Segment, wie die Tabelle sagt, auch wenn das Flag widerspricht. Das Flag zählt nur bei unbekannten Typen (A5.1, Versionsregel). Typen 0x8000–0xFFFF werden immer ignoriert, gleich was das Flag sagt. `ENCRYPTED` ist genau bei den Nutzdaten gesetzt, die verschlüsselt sind (PACK, INDEX, INDEX_COPY eines verschlüsselten Archivs, A11).

Das magische `AHSG` erlaubt es, Segmente bei beschädigtem Index durch Suchen in der Datei wiederzufinden.

### A5.3 PACK-Nutzdaten

```
pack_header (CBOR-Map, Länge vorangestellt als u32):
  { "codec": uint, "ulen": uint, "chunks": uint, "level": uint (informativ) }
compressed_data
```

Die Chunks eines Packs werden in der Reihenfolge der Chunk-Tabelle (Index) hintereinander gelegt und als ein Block komprimiert. Ihre Lage im unkomprimierten Pack steht in der Chunk-Tabelle.

**Codec-Register:**

| ID | Codec | Hinweis |
|---|---|---|
| 0 | none | für nicht komprimierbare Daten (JXL, MP4, HEIC …) |
| 1 | zstd | Standard für „Schnell“; Frame-Format nach RFC 8878 |
| 2 | LZMA2 | Rohdatenstrom, Parameter (dict_size) im pack_header als `"dict"` |
| 3–15 | reserviert | z. B. Brotli, Context Mixing |

**Regel:** Spart ein Codec weniger als 2 % (bei der Stufe „Maximal“ 0,5 %) gegenüber `none`, wird `none` gespeichert. Die Regel betrifft nur den Packer; ein Decoder liest jeden Codec.

**Grenzen:** `ulen` eines Packs höchstens 64 MiB, CBOR-pack_header höchstens 4 KiB, `dict` bei LZMA2 zwischen 4 KiB und 256 MiB. `ulen` und `codec` im pack_header müssen mit dem Eintrag in der Pack-Tabelle des Index übereinstimmen.

### A5.4 Footer (letzte 64 Byte der Datei)

| Offset | Größe | Feld |
|---|---|---|
| 0 | 8 | magic `AHYEND\0\0` |
| 8 | 2 | format_major |
| 10 | 2 | format_minor |
| 12 | 4 | flags (Archiv-Flags, A5.1; hier **maßgeblich** für den Stand dieser Generation) |
| 16 | 8 | index_offset (Offset des INDEX-Segmentkopfs) |
| 24 | 8 | index_copy_offset |
| 32 | 8 | recovery_offset (Offset des Segmentkopfs des neuesten RECOVERY-Segments, 0 = keine) |
| 40 | 8 | generation |
| 48 | 8 | key_info_offset (Format 1.1 verschlüsselt: Offset des KEY_INFO-Segmentkopfs dieser Generation; sonst 0) |
| 56 | 4 | reserved |
| 60 | 4 | crc32c über Byte 0–59 |

Ein Footer folgt direkt auf das letzte Segment seiner Generation (INDEX_COPY, oder RECOVERY, wenn die Generation eines schreibt). Bytes, die anderswo wie ein Footer aussehen, etwa in der Parität eines RECOVERY-Segments (A9), sind kein Footer: Ein Decoder nimmt einen Footer nur an, wenn das Segment am größten der Werte `index_offset`, `index_copy_offset` und `recovery_offset` genau am Footer endet, außer dieser Segmentkopf ist unlesbar.

**Öffnen eines Archivs:** Header prüfen → Footer lesen → INDEX lesen und Hash prüfen. Bei einem Fehler wird INDEX_COPY verwendet. Ist der Footer selbst kaputt, sucht der Decoder vom Dateiende rückwärts nach dem letzten gültigen `AHYEND` bzw. INDEX-Segment.

## A6. Inhaltsverzeichnis (INDEX)

CBOR-Map, danach zstd-komprimiert (Codec in einem 1-Byte-Präfix: 1 = zstd).

```
{
  "v": 1,                         ; Indexversion
  "generation": uint,
  "created_ns": int,
  "cdc": { "alg": "fastcdc-2020", "min": 65536, "avg": 262144, "max": 1048576 },
  "packs": [ { "off": uint, "clen": uint, "ulen": uint, "codec": uint, "hash": bstr(16) } ... ],
                                  ; off = Offset des PACK-Segmentkopfs, clen = Länge von compressed_data,
                                  ; hash = BLAKE3-128 der ganzen Nutzdaten (= payload_hash des Segmentkopfs)
  "chunks": {                     ; spaltenweise für Kompaktheit
    "id":     bstr(32 × n),       ; BLAKE3-256 je Chunk, hintereinander
    "pack":   [uint ...],         ; Index in "packs"
    "off":    [uint ...],         ; Offset im unkomprimierten Pack
    "len":    [uint ...]
  },
  "snapshots": [ Snapshot ... ]   ; alle Versionen, älteste zuerst
}

Snapshot = {
  "id": uint, "time_ns": int, "comment": tstr, "source": tstr (Namen dessen, was gepackt wurde, z. B. „Fotos, Dokumente“; informativ, nie ein absoluter Pfad),
  "entries": [ Entry ... ]
}

Entry = {
  "path": bstr, "path_nfc": tstr,
  "kind": 0 Datei | 1 Ordner | 2 Symlink | 3 Hardlink,
  "mode": uint, "mtime_ns": int, "btime_ns": int (optional),
  "xattr": { tstr: Stream ... } (optional; macOS: Finder-Tags, Quarantäne, Resource Fork),
  "target": bstr (Symlink-Ziel bzw. Pfad des Hardlink-Originals),
  "size": uint, "hash": bstr(32),          ; BLAKE3-256 der Originaldatei
  "recipe": Recipe                          ; nur bei Dateien
}

Stream = [ uint ... ]            ; Indizes in die Chunk-Tabelle
Recipe = [ Part ... ]            ; Originaldatei = Verkettung der Teil-Ausgaben
Part   = [ transform_id: uint, params: map, inputs: [ Stream ... ] ]
```

`source` dient nur der Anzeige. Ein Packer schreibt dort keinen absoluten Pfad (auch keinen, der mit `~` beginnt oder mit `..` nach oben geht): Sonst verriete das Archiv, wo die Dateien auf dem packenden Rechner lagen. Schreibt er einen neuen Index, kürzt er solche Werte älterer Snapshots auf ihren letzten Namen.

Regeln für Einträge:

- `size`, `hash` und `recipe` gibt es nur bei Dateien (`kind` 0).
- Ein Hardlink (`kind` 3) verweist mit `target` auf den Pfad einer **Datei im selben Snapshot**; seine Daten sind die dieser Datei.
- Die Werte von `xattr` sind Streams wie Dateiinhalte (lange Werte werden also ebenfalls zerlegt und dedupliziert).
- `mode` enthält nur die Rechte-Bits (`0o7777`), die Art steht in `kind`.
- Ein Packer legt die Einträge nach den Bytes von `path` sortiert ab; ein Decoder darf sich darauf nicht verlassen.

Identische Dateien verweisen auf dieselben Chunks (Deduplizierung auf Dateiebene ergibt sich daraus automatisch). Der Index einer neuen Generation enthält immer alle verbliebenen Snapshots und alle Packs und Chunks des Archivs, auch solche, die kein Snapshot mehr benutzt (sie entfallen erst beim Optimieren, A10); ältere INDEX-Segmente sind danach nur noch Historie.

## A7. Transformationen

Ein Rezept besteht aus Teilen. Jeder Teil erzeugt aus seinen Eingabe-Streams einen Abschnitt der Originaldatei.

| ID | Name | Eingaben | Parameter | Ausgabe |
|---|---|---|---|---|
| 0 | RAW | 1 Stream | – | Stream unverändert |
| 1 | ZLIB_EXACT | 1 Stream (entpackte Daten) | `wbits`, `level`, `memlevel`, `strategy`, `impl` (Register siehe unten) | Deflate-Strom, der mit genau dieser zlib-Version und diesen Parametern entsteht |
| 2 | PREFLATE | 2 Streams (entpackte Daten, Korrekturdaten) | `ver` (preflate-Version), `wbits` | Original-Deflate-Strom beliebiger Herkunft |
| 3 | JPEG_FROM_JXL | 1 Stream (JPEG-XL-Codestream mit JPEG-Rekonstruktionsdaten) | `enc` (informativ, z. B. `"libjxl 0.11"`) | Original-JPEG nach ISO/IEC 18181-2 (JPEG-Bitstream-Rekonstruktion) |
| 4–63 | reserviert | | | z. B. PNG_IDAT, GZIP-Datei, MP3, HEIC |

**Hinweise:**

- **ZLIB_EXACT** ist der schnelle Weg für Daten, die von zlib selbst stammen. Der Decoder muss die angegebene zlib-Version mitliefern (vendored), denn andere Implementierungen (zlib-ng, libdeflate, die von Apple) erzeugen andere Bytes. Erlaubte Parameterwerte (wie bei `deflateInit2` von zlib): `wbits` 8 bis 15 (zlib-Hülle), −9 bis −15 (rohes Deflate; −8 ist nicht erlaubt, weil zlib es stillschweigend zu −9 macht) oder 24 bis 31 (gzip-Hülle); `level` 0 bis 9; `memlevel` 1 bis 9; `strategy` 0 bis 4. Andere Werte meldet der Decoder als Schaden. Register der Werte für `impl`: `"zlib-1.3.1"` (unveränderter Quelltext von zlib 1.3.1). Neue Werte kommen nur mit Testvektoren hinzu; eine einmal vergebene Version bleibt für immer lesbar, der Decoder liefert sie also dauerhaft mit, auf allen Plattformen. Einen unbekannten Wert meldet der Decoder als Fehler.
- **PREFLATE** rekonstruiert auch Deflate-Ströme aus Microsoft Office, Adobe usw. Die Korrekturdaten sind meist sehr klein. Der Parameter `ver` bezeichnet das Format der Korrekturdaten, nicht nur eine Softwareversion; jedes vergebene `ver` bleibt dauerhaft lesbar. Register der Werte für `ver`: `"preflate-rs-0.7.6/archydes-rc-1"`. Referenz dafür ist ein Fork von preflate-rs 0.7.6 (`vendor/preflate-rs`, Apache-2.0), dessen Korrekturdaten ein eigener adaptiver binärer Range-Coder nach dem Schema von LZMA kodiert (11-Bit-Wahrscheinlichkeiten, Anpassung um 1/32). Die Byte-Folge ist in `FORK.md` des Forks beschrieben und durch Testvektoren festgelegt. Die Korrekturdaten sind deshalb nicht mit dem unveränderten preflate-rs austauschbar. `wbits` ist immer `-15`: Die Ausgabe ist ein roher Deflate-Strom ohne Hülle. Eine zlib-Hülle (2 Byte Kopf, 4 Byte Adler-32) steht in RAW-Teilen davor und dahinter. Einen unbekannten Wert von `ver` meldet der Decoder als Fehler.
- **JPEG_FROM_JXL** ist im JPEG-XL-Standard normiert. Damit ist die Rekonstruktion langfristig nicht von einer bestimmten Software abhängig. Das ist ein wichtiges Argument für die Langzeitsicherheit. Nicht jedes JPEG lässt sich so darstellen (z. B. arithmetische Kodierung, manche CMYK- oder beschädigte Dateien). Solche Dateien erkennt die Pflichtprüfung, sie werden RAW gespeichert.

**Vorverarbeiter (nur im Packer, nicht Teil des Formats):** Sie zerlegen eine Datei in Teile.

| Dateityp | Vorgehen |
|---|---|
| JPEG | ganze Datei → JPEG_FROM_JXL |
| PDF | Teile: RAW (Rest), JPEG_FROM_JXL (Ströme mit `/DCTDecode`), ZLIB_EXACT/PREFLATE (Ströme mit `/FlateDecode`) |
| ZIP-Container (DOCX, XLSX, PPTX, ODT, EPUB, ZIP, Pages …) | RAW (Köpfe, Verzeichnis), ZLIB_EXACT/PREFLATE (Einträge mit Methode 8), JPEG_FROM_JXL (gespeicherte JPEGs, Methode 0). Ein JPEG in einem Deflate-Eintrag wird nur entpackt, nicht zusätzlich umgewandelt |
| alles andere | RAW |

Später: PNG (IDAT-Ströme verketten), GZIP-Dateien, JPEGs in anderen Containern.

**Pflichtprüfung beim Packen:** Für jede Datei wird das Rezept sofort zurückgerechnet und mit dem BLAKE3-Hash des Originals verglichen. Nur bei Übereinstimmung wird das Rezept verwendet, sonst RAW. Zurückgerechnet wird mit **demselben Decoder-Code wie im offenen Entpack-Tool**, nicht mit dem Encoder. So ist gesichert, dass das offene Tool jede geschriebene Datei bitgenau entpacken kann. Beim Entpacken wird der Hash immer geprüft.

## A8. Chunking und Packs

- Die Ausgabe-Streams der Vorverarbeiter werden mit **FastCDC** (inhaltsbasiert) zerlegt: min 64 KiB, Durchschnitt 256 KiB, max 1 MiB. Die Parameter stehen im Index. Kleinere Dateien bilden einen einzigen Chunk.
- Chunk-ID = BLAKE3-256 des Chunk-Inhalts. Bei einer bereits bekannten ID wird der Chunk nicht erneut gespeichert.
- Chunks werden nach **Typklasse** auf Packs verteilt, damit die solide Kompression gut funktioniert: Text/XML, Binärdaten, bereits entropiekodiert (JXL, HEIC, MP4 …). Innerhalb einer Klasse nach Dateiendung und Pfad sortieren.
- Ziel-Packgröße 16 MiB unkomprimiert. Packs sind unabhängig und werden parallel komprimiert.

**Voreinstellungen** (Empfehlung für Packer, nicht Teil des Formats):

| Stufe | Codec | Transformationen | Zweck |
|---|---|---|---|
| Schnell | zstd 3 | keine | Alltag, sehr schnell |
| Standard | zstd 19 bzw. LZMA2 für Text | JPEG, JPEG in PDF, ZLIB_EXACT | gute Mischung |
| Maximal | LZMA2 (preset 9e) | alle inkl. PREFLATE | Archivierung |

## A9. Wiederherstellungsdaten (RECOVERY)

**Abdeckung.** Jedes RECOVERY-Segment schützt einen zusammenhängenden Bereich `[start, end)` der Datei. `end` ist der Offset seines eigenen Segmentkopfs. `start` ist das Ende des vorigen RECOVERY-Segments (Segmentkopf plus Nutzdaten), 0 beim ersten. Die Kette aller RECOVERY-Segmente deckt also lückenlos die Datei bis zum neuesten RECOVERY-Segment ab, Dateikopf eingeschlossen. Ältere RECOVERY-Segmente und Footer liegen im Bereich der jeweils neueren und sind damit selbst geschützt. Ein Packer schreibt RECOVERY nach INDEX und INDEX_COPY und unmittelbar vor den Footer; `recovery_offset` im Footer zeigt darauf, das Archiv-Flag `RECOVERY` (A5.1) ist gesetzt. Das Segment ist nicht kritisch (Segment-Flag `CRITICAL` aus, A5.2): Ein Decoder ohne Reparatur darf es überspringen.

**Scheiben und Gruppen.**

- Der Bereich wird in `N = ceil((end − start) / 65536)` Scheiben zu **64 KiB** geteilt. Die letzte Scheibe wird für Hash und Kodierung mit Nullbytes auf 64 KiB aufgefüllt; die Nullen werden nicht gespeichert.
- Es gibt `G = ceil(N / 1024)` Gruppen. Die Scheiben werden **verschränkt** verteilt: Scheibe `i` gehört zu Gruppe `i mod G` und ist dort die Originalscheibe Nummer `i div G`. Gruppe `g` hat damit `n_g = ceil((N − g) / G)` Datenscheiben (höchstens 1024) und `r_g = max(1, ceil(n_g × Anteil))` Paritätsscheiben.
- Grund für die Verschränkung: Ein zusammenhängender Schaden (defekter Sektor, abgeschnittener Download, überschriebener Block) verteilt sich gleichmäßig auf alle Gruppen. Ein Block aus bis zu `Σ r_g − G` aufeinanderfolgenden Scheiben ist immer reparierbar, also fast die gesamte Parität. Gleichzeitig braucht das Kodieren je Gruppe nur 64 MiB Speicher.
- Redundanz einstellbar: 0 % (aus), 5 % (Standard), 10 % oder 20 %, je Generation. Der Decoder liest den Anteil nicht, sondern nur `[n_g, r_g]` aus dem Kopf.

**Aufbau der Nutzdaten.** Alle Zahlen little-endian.

| Teil | Inhalt |
|---|---|
| Kopf vorn | `u32 H`, `H` Bytes CBOR, `u32` CRC32C der CBOR-Bytes |
| Parität | für `g = 0 … G−1` die `r_g` Paritätsscheiben der Gruppe, je 65 536 Bytes |
| Tabelle | BLAKE3-128 jeder Datenscheibe (`i = 0 … N−1`), dann jeder Paritätsscheibe in der Reihenfolge oben; danach `u32` CRC32C der Tabelle |
| Tabelle, Kopie | dieselben Bytes noch einmal |
| Kopf hinten | `H` Bytes CBOR, `u32` CRC32C, `u32 H` |

Kopf: `{"v": 1, "alg": "rs-leopard-gf16", "slice": 65536, "start": uint, "end": uint, "groups": [[n, r] ...], "prev": uint}`. `prev` ist der Offset des vorigen RECOVERY-Segments, 0 beim ersten. Ein Decoder prüft, dass `groups` genau der Verschränkung von `[start, end)` entspricht, und lehnt den Kopf sonst ab.

**Selbstschutz.** Das neueste RECOVERY-Segment und der letzte Footer liegen hinter dem geschützten Bereich. Deshalb:

- Die Tabelle enthält auch die Hashes der **Paritätsscheiben**. Eine beschädigte Paritätsscheibe zählt wie eine fehlende Scheibe. Eine Gruppe ist reparierbar, solange beschädigte Daten- und Paritätsscheiben zusammen höchstens `r_g` sind. Ein Schaden im Paritätsteil kostet nur Kapazität.
- Kopf und Tabelle stehen je zweimal und tragen eine eigene CRC32C. Ist bei beiden Tabellenkopien die CRC falsch, gilt eine Scheibe als intakt, wenn ihr Hash mit einer der beiden Kopien übereinstimmt.
- Der Footer enthält nur Offsets, die sich aus den Segmenten neu bestimmen lassen. `archydes repair` schreibt ihn neu.

**Auffinden.** Der Decoder sucht das RECOVERY-Segment in dieser Reihenfolge, ohne Footer oder Segmentkopf vorauszusetzen:

1. über `recovery_offset` des letzten Footers;
2. über den hinteren Kopf, der direkt vor dem Footer endet (oder am Dateiende, wenn der Footer fehlt);
3. durch Rückwärtssuche nach einem gültigen Segmentkopf vom Typ RECOVERY.

In jedem Fall muss `end` gleich dem Offset des Segments sein und das Segment ganz in der Datei liegen.

**Reparieren.**

1. Jede Daten- und Paritätsscheibe wird gegen die Tabelle geprüft.
2. Jede Gruppe mit beschädigten Datenscheiben wird dekodiert, wenn genug intakte Scheiben übrig sind. Jede wiederhergestellte Scheibe wird vor dem Zurückschreiben noch einmal gegen die Tabelle geprüft.
3. Sind danach alle Daten intakt und war RECOVERY selbst beschädigt, wird das RECOVERY-Segment mit demselben Aufbau neu geschrieben. Bleibt Datenschaden übrig, bleibt RECOVERY unverändert, damit keine Parität über beschädigte Daten entsteht.
4. Ist der Footer hinter dem RECOVERY-Segment unbrauchbar, wird er neu geschrieben, aus dem letzten INDEX und INDEX_COPY vor dem RECOVERY-Segment (verschlüsselt auch der KEY_INFO-Kopie davor). Seine Flags sind die, die ein Packer schreibt: `ENCRYPTED` aus dem Dateikopf (es kann sich nicht ändern), `RECOVERY`, und `MULTIPLE_SNAPSHOTS`, wenn der Index mehr als einen Snapshot enthält. Ohne Passwort ist der Index eines verschlüsselten Archivs nicht lesbar; dann kommen `MULTIPLE_SNAPSHOTS` und `generation` (plus 1) aus dem vorigen Footer. Der Dateikopf darf für `MULTIPLE_SNAPSHOTS` nicht verwendet werden: Er zeigt den Zustand bei der Erstellung.

**Kette.** Ältere Bereiche erreicht der Decoder über `prev`: Das vorige RECOVERY-Segment wird über seinen vorderen Kopf gefunden (`prev` + 40) oder, wenn der beschädigt ist, über den hinteren Kopf, der genau an `start` des neueren Bereichs endet. Es muss `end = prev` und Segmentende `= start` des neueren Bereichs gelten; die Bereiche sind lückenlos und überschneiden sich nicht. `repair` prüft und repariert jeden Bereich der Kette, den neuesten zuerst; Schritt 4 (Footer) betrifft nur den neuesten. Hat eine Generation kein RECOVERY (Anteil 0), zeigt ihr Footer weiter auf das vorige Segment und behält das Flag `RECOVERY`, solange `recovery_offset` nicht 0 ist; die Generation selbst ist dann ungeschützt, und das nächste RECOVERY-Segment deckt alles seitdem mit ab.

Ist eine Gruppe nicht reparierbar, bleiben alle Dateien entpackbar, deren Packs außerhalb des Schadens liegen. Der Bericht nennt die betroffenen Dateien.

**Grenze.** Wird die Datei **abgeschnitten**, fehlt zuerst das RECOVERY-Segment, denn es steht am Ende. Dann hilft nur die Rückwärtssuche nach dem letzten lesbaren Index (A5.4). Eine spätere Option ist eine separate Recovery-Datei neben dem Archiv.

**Verfahren `rs-leopard-gf16`.** Reed-Solomon-Erasure-Code über GF(2^16) nach Leopard-RS (C. A. Taylor), Scheibengröße ein Vielfaches von 64 Byte. Referenz ist die Rust-Bibliothek `reed-solomon-simd` ab 3.0. Eine mathematische Beschreibung (Körperpolynom, Basis, Anordnung der Scheiben) folgt in einer späteren Fassung dieses Abschnitts, damit unabhängige Implementierungen ohne diese Bibliothek möglich sind. Die Testvektoren legen die Kodierung zusätzlich fest.

## A10. Versionen (Snapshots)

**Generationen.** Ein Archiv wächst nur am Ende. Jede Generation hängt an das Ende des letzten gültigen Footers an: neue PACK-Segmente (nur Chunks, die das Archiv noch nicht hat), dann in verschlüsselten Archiven eine Kopie von KEY_INFO (A11), dann INDEX und INDEX_COPY mit **allen** Snapshots, Chunks und Packs, dann optional RECOVERY über den neuen Bereich (A9), dann den Footer. `generation` steigt um 1. Was vor dem Ende des letzten gültigen Footers steht, wird nie wieder geschrieben.

**Gültigkeit.** Eine Generation gilt erst, wenn ihr Footer vollständig geschrieben ist. Ein Packer sichert alles vor dem Footer mit `fsync`, schreibt dann den Footer und sichert ihn ebenfalls. Bei einem Absturz davor findet der Decoder über die Rückwärtssuche (A5.4) den Footer der vorigen Generation; diese ist unverändert lesbar.

**Reste eines abgebrochenen Anhängens.** Ein Decoder, der den letzten Footer nicht lesen kann und über die Rückwärtssuche einen gültigen Footer mit lesbarem INDEX findet, prüft die Bytes dahinter. Sie gelten als Rest eines abgebrochenen Anhängens und gehören nicht zum Archiv, wenn

- vom Ende des gefundenen Footers an nur Segmente der Typen PACK, KEY_INFO (bei verschlüsselten Archiven, A11), INDEX, INDEX_COPY und RECOVERY folgen, das letzte davon möglicherweise unvollständig (Kopf abgeschnitten, aus Nullbytes, oder Nutzdaten über das Dateiende hinaus), und kein lesbarer Footer;
- die letzten 64 Byte der Datei nicht mit der Footer-Kennung beginnen;
- kein INDEX_COPY- oder RECOVERY-Segment genau 64 Byte vor dem Dateiende endet.

Die beiden letzten Bedingungen erkennen eine vollständige neuere Generation mit beschädigtem Footer; sie ist kein Rest, sondern ein Schaden, den `repair` beheben kann. `verify` meldet Reste als Hinweis, nicht als Schaden. Der nächste Schreibvorgang schneidet sie ab, bevor er anhängt; ein Archiv mit Schaden verändert er nicht.

**Gleichzeitiger Zugriff.** Ein Packer sperrt das Archiv beim Anhängen exklusiv (`flock`/`LockFileEx`) und bricht ab, wenn es schon gesperrt ist. Leser brauchen keine Sperre: Was vor dem Footer steht, den sie benutzen, ändert sich nicht.

**Snapshot-Nummern.** Ein neuer Snapshot bekommt die größte vorhandene `id` plus 1. Nummern werden nicht wiederverwendet, auch nicht nach dem Löschen.

**Snapshot löschen.** Eine neue Generation ohne PACK-Segmente: (verschlüsselt: KEY_INFO-Kopie,) INDEX und INDEX_COPY ohne die gelöschten Snapshots, optional RECOVERY, Footer. Chunks und Packs bleiben im Index und in der Datei (A6), bis das Archiv optimiert wird; der letzte Snapshot kann nicht gelöscht werden.

**Optimieren.** Schreibt das Archiv neu, mit nur den Chunks, die ein Snapshot noch benutzt (Rezepte und erweiterte Attribute). Packs, deren Chunks alle benutzt sind, werden unverändert übernommen, teilweise benutzte entpackt und neu gepackt, unbenutzte entfallen. `archive_uuid` und `created_ns` des Dateikopfs bleiben, `generation` steigt um 1, RECOVERY deckt die ganze neue Datei ab. Die neue Datei ersetzt die alte durch Umbenennen.

## A11. Verschlüsselung (Format 1.1)

Ein verschlüsseltes Archiv hat `format_minor = 1` und Bit 0 (verschlüsselt) in Header und jedem Footer. Unverschlüsselte Archive bleiben Format 1.0.

**Was verschlüsselt ist.** Die Nutzdaten der Segmente PACK, INDEX und INDEX_COPY. Klartext bleiben FORMAT_INFO, KEY_INFO und RECOVERY. PLAIN_TOC ist verboten. Damit sind Inhalte, Namen, Größen und Daten einzelner Dateien, Kommentare, erweiterte Attribute und Chunk-IDs geschützt. Sichtbar bleiben Gesamtgröße, Anzahl und Größe der Segmente, Zahl der Generationen, Erstellzeit und die Argon2-Parameter.

**Schlüssel.**

```
KEK     = Argon2id v1.3 (Passwort als UTF-8 in Unicode-NFC, salt, m, t, p), 32 Byte
DEK     = 32 zufällige Bytes je Archiv, in KEY_INFO unter KEK eingepackt
k_seg   = BLAKE3-derive_key("archydes 2026-11 segment v1", DEK)
k_chunk = BLAKE3-derive_key("archydes 2026-11 chunk-id v1", DEK)
```

**KEY_INFO** (Typ 0x0007, kritisch, unverschlüsselt). Steht beim Erstellen direkt hinter FORMAT_INFO; jede Generation schreibt vor ihren INDEX eine bytegleiche Kopie, auf die `key_info_offset` ihres Footers zeigt. Nutzdaten: CBOR-Map

```
{ "v": 1, "kdf": "argon2id-1.3", "m": uint (KiB), "t": uint, "p": uint, "salt": bstr(16),
  "aead": "xchacha20-poly1305", "nonce": bstr(24), "wrapped": bstr(48) }
```

`wrapped` = XChaCha20-Poly1305(KEK, nonce, DEK, AAD) mit 16 Byte Etikett am Ende. AAD = `"archydes key v1"` (ASCII, 15 Byte) ‖ `archive_uuid` (16 Byte) ‖ deterministisches CBOR der Map ohne `nonce` und `wrapped`. Ein Decoder lehnt ab, ohne zu rechnen, wenn `v`, `kdf` oder `aead` unbekannt sind oder die Grenzen verletzt sind: `m` 8 192 bis 4 194 304 (8 MiB bis 4 GiB), `t` 1 bis 64, `p` 1 bis 64, `m ≥ 8·p`. Scheitert das Etikett, ist das Passwort falsch.

Auffinden: über `key_info_offset` des benutzten Footers; ist das Segment dort unbrauchbar, die erste lesbare KEY_INFO im Durchlauf vom Dateianfang (A5). Alle KEY_INFO-Segmente eines Archivs sind gleich.

**Verschlüsselte Segmente.** Gespeichert wird `nonce (24 Byte) ‖ Chiffrat ‖ Etikett (16 Byte)`, verschlüsselt mit `k_seg` und einer zufälligen Nonce je Segment. Der Segmentkopf trägt Flag Bit 1 (verschlüsselt); `payload_len` und `payload_hash` beziehen sich auf die gespeicherten Bytes. Prüfen der Struktur, Wiederherstellung und Reparatur brauchen deshalb kein Passwort. AAD = `"archydes segment v1"` (ASCII, 19 Byte) ‖ `archive_uuid` ‖ Klasse (1 Byte: 1 = PACK, 2 = INDEX für INDEX und INDEX_COPY). INDEX_COPY ist bytegleich mit INDEX. Entschlüsselt ergibt sich der bisherige Inhalt: pack_header und komprimierte Daten (A5.3) bzw. Codec-Byte und Index (A6). `clen` im Index ist die Länge der komprimierten Daten vor dem Verschlüsseln, `hash` der Pack-Tabelle der `payload_hash` des Segments (über das Chiffrat).

**Regeln für Decoder.** In einem verschlüsselten Archiv müssen PACK, INDEX und INDEX_COPY verschlüsselt sein, in einem unverschlüsselten darf kein Segment das Flag tragen; sonst gilt das Archiv als beschädigt. Ein fehlerhaftes Etikett eines PACK oder INDEX ist ein Schaden wie ein falscher `payload_hash`.

**Chunk-IDs.** Bei Verschlüsselung `BLAKE3-keyed(k_chunk, Inhalt)` statt BLAKE3-256. Der Datei-Hash im Eintrag (`hash`) bleibt BLAKE3-256 der Originaldatei.

**Grenzen.** Wer Schreibzugriff hat, kann die neueste Generation abschneiden; das Archiv liest sich dann wie davor. Jede Veränderung der Daten wird erkannt.

## A12. Sicherheit beim Entpacken

- Pfade mit `..`, absolute Pfade und leere Pfadteile ablehnen (Zip-Slip).
- Symlinks: nie außerhalb des Zielordners auflösen. Standardmäßig als Symlink anlegen, nicht folgen.
- Grenzen gegen Dekompressionsbomben: Index entpackt höchstens 1 GiB, Packs höchstens 64 MiB (A5.3), CBOR höchstens 32 Ebenen tief, keine Länge darf über das Ende der Eingabe hinausreichen. Beim Entpacken einer Datei wird abgebrochen, sobald mehr Daten entstehen als `size` angibt. Gesamtgröße vorab aus dem Index prüfen.
- Reihenfolge beim Entpacken: Ordner, Dateien, Hardlinks, **Symlinks zuletzt**, danach die Metadaten der Ordner von innen nach außen. Jeder übergeordnete Pfadteil muss ein echter Ordner sein (kein Symlink). So wird nie durch einen Symlink aus dem Archiv geschrieben.
- setuid- und setgid-Bits werden standardmäßig nicht wiederhergestellt. Vorhandene Dateien werden standardmäßig nicht überschrieben.
- Eine Datei, deren Hash nicht stimmt, wird wieder gelöscht und als beschädigt gemeldet; die übrigen Dateien werden trotzdem entpackt.
- Alle Parser (Header, Segmente, CBOR, Rezepte) behandeln Eingaben als nicht vertrauenswürdig und werden gefuzzt.

## A13. Dateiendung und Kennung

- Dateiendung: **`.archy`**.
- UTI (macOS): `do.com.solit.archydes.archive`, konform zu `public.data` und `public.archive`.
- MIME-Typ: `application/x-archydes`.

## A14. Testvektoren und Konformität

Zur Spezifikation gehört ein Ordner `testvectors/` mit kleinen Archiven und den erwarteten Inhalten: leeres Archiv, einzelne Datei, Deduplizierung, jede Transformation, Wiederherstellung (mit gezielt beschädigter Kopie), mehrere Generationen, ein verschlüsseltes Archiv mit bekanntem Passwort und Known-Answer-Werte für Schlüsselableitung, Einpacken des Datenschlüssels, Teilschlüssel und Versiegeln (A11). Jede Implementierung muss diese Vektoren bestehen.

