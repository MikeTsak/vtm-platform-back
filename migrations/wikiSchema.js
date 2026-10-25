// back/migrations/wikiSchema.js
// Idempotently provisions the 14 wiki tables in the dedicated wiki database.
const wikiPool = require('../wikiDb');
const { log } = require('../logger');

const WIKI_TABLE_DDLS = [
  `CREATE TABLE IF NOT EXISTS \`wiki_categories\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`parent_id\` int(11) DEFAULT NULL,
    \`name\` varchar(255) NOT NULL,
    \`slug\` varchar(255) NOT NULL,
    \`created_at\` timestamp NULL DEFAULT current_timestamp(),
    PRIMARY KEY (\`id\`),
    UNIQUE KEY \`slug\` (\`slug\`),
    KEY \`parent_id\` (\`parent_id\`),
    CONSTRAINT \`wiki_categories_ibfk_1\` FOREIGN KEY (\`parent_id\`) REFERENCES \`wiki_categories\` (\`id\`) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_articles\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`category_id\` int(11) DEFAULT NULL,
    \`author_id\` int(11) NOT NULL,
    \`title\` varchar(255) NOT NULL,
    \`slug\` varchar(255) NOT NULL,
    \`content\` longtext NOT NULL,
    \`status\` enum('draft','published','private') DEFAULT 'draft',
    \`created_at\` timestamp NULL DEFAULT current_timestamp(),
    \`updated_at\` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
    PRIMARY KEY (\`id\`),
    UNIQUE KEY \`slug\` (\`slug\`),
    KEY \`category_id\` (\`category_id\`),
    KEY \`idx_status\` (\`status\`),
    CONSTRAINT \`wiki_articles_ibfk_1\` FOREIGN KEY (\`category_id\`) REFERENCES \`wiki_categories\` (\`id\`) ON DELETE SET NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_article_versions\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`article_id\` int(11) NOT NULL,
    \`editor_id\` int(11) NOT NULL,
    \`content\` longtext NOT NULL,
    \`edit_summary\` varchar(500) DEFAULT NULL,
    \`created_at\` timestamp NULL DEFAULT current_timestamp(),
    PRIMARY KEY (\`id\`),
    KEY \`article_id\` (\`article_id\`),
    CONSTRAINT \`wiki_article_versions_ibfk_1\` FOREIGN KEY (\`article_id\`) REFERENCES \`wiki_articles\` (\`id\`) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_tags\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`name\` varchar(255) NOT NULL,
    \`slug\` varchar(255) NOT NULL,
    \`created_at\` timestamp NULL DEFAULT current_timestamp(),
    PRIMARY KEY (\`id\`),
    UNIQUE KEY \`slug\` (\`slug\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_article_tags\` (
    \`article_id\` int(11) NOT NULL,
    \`tag_id\` int(11) NOT NULL,
    PRIMARY KEY (\`article_id\`,\`tag_id\`),
    KEY \`tag_id\` (\`tag_id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_admin_notes\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`article_id\` int(11) NOT NULL,
    \`author_id\` int(11) NOT NULL,
    \`content\` longtext DEFAULT NULL,
    \`created_at\` timestamp NULL DEFAULT current_timestamp(),
    \`updated_at\` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
    PRIMARY KEY (\`id\`),
    KEY \`article_id\` (\`article_id\`),
    KEY \`author_id\` (\`author_id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_boards\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`owner_id\` int(11) NOT NULL,
    \`name\` varchar(255) NOT NULL,
    \`description\` text DEFAULT NULL,
    \`visibility\` enum('private','shared','public','admin_only') DEFAULT 'private',
    \`created_at\` timestamp NULL DEFAULT current_timestamp(),
    PRIMARY KEY (\`id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_board_items\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`board_id\` int(11) NOT NULL,
    \`user_id\` int(11) NOT NULL,
    \`content\` text NOT NULL,
    \`created_at\` timestamp NULL DEFAULT current_timestamp(),
    PRIMARY KEY (\`id\`),
    KEY \`board_id\` (\`board_id\`),
    CONSTRAINT \`wiki_board_items_ibfk_1\` FOREIGN KEY (\`board_id\`) REFERENCES \`wiki_boards\` (\`id\`) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_board_members\` (
    \`board_id\` int(11) NOT NULL,
    \`user_id\` int(11) NOT NULL,
    \`role\` enum('viewer','editor') DEFAULT 'viewer',
    PRIMARY KEY (\`board_id\`,\`user_id\`),
    CONSTRAINT \`wiki_board_members_ibfk_1\` FOREIGN KEY (\`board_id\`) REFERENCES \`wiki_boards\` (\`id\`) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_elysium_boards\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`title\` varchar(255) NOT NULL,
    \`data\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`data\`)),
    \`created_at\` datetime DEFAULT current_timestamp(),
    \`updated_at\` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
    \`visibility\` varchar(50) DEFAULT 'public',
    \`owner_id\` int(11) DEFAULT NULL,
    PRIMARY KEY (\`id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_elysium_board_members\` (
    \`board_id\` int(11) NOT NULL,
    \`user_id\` int(11) NOT NULL,
    \`added_at\` datetime DEFAULT current_timestamp(),
    PRIMARY KEY (\`board_id\`,\`user_id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_journal_entries\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`user_id\` int(11) NOT NULL,
    \`title\` varchar(255) NOT NULL DEFAULT 'Untitled Entry',
    \`content\` longtext DEFAULT NULL,
    \`created_at\` timestamp NULL DEFAULT current_timestamp(),
    \`updated_at\` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
    PRIMARY KEY (\`id\`),
    KEY \`user_id\` (\`user_id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_notes\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`article_id\` int(11) DEFAULT NULL,
    \`user_id\` int(11) NOT NULL,
    \`content\` text NOT NULL,
    \`created_at\` timestamp NULL DEFAULT current_timestamp(),
    \`updated_at\` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
    PRIMARY KEY (\`id\`),
    UNIQUE KEY \`unique_user_article_note\` (\`user_id\`,\`article_id\`),
    KEY \`article_id\` (\`article_id\`),
    CONSTRAINT \`wiki_notes_ibfk_1\` FOREIGN KEY (\`article_id\`) REFERENCES \`wiki_articles\` (\`id\`) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci`,

  `CREATE TABLE IF NOT EXISTS \`wiki_timeline_events\` (
    \`id\` int(11) NOT NULL AUTO_INCREMENT,
    \`title\` varchar(255) NOT NULL,
    \`date_label\` varchar(200) NOT NULL,
    \`description\` text DEFAULT NULL,
    \`article_slug\` varchar(255) DEFAULT NULL,
    \`category\` varchar(100) DEFAULT 'General',
    \`sort_order\` int(11) DEFAULT 0,
    \`created_by\` int(11) DEFAULT NULL,
    \`created_at\` timestamp NULL DEFAULT current_timestamp(),
    PRIMARY KEY (\`id\`),
    KEY \`article_slug\` (\`article_slug\`),
    KEY \`sort_order\` (\`sort_order\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
];

async function seedClanArticles(conn) {
  const articles = [
    {
      slug: 'Athens_Through_Time_Clan_Translations',
      title: 'Athens Through Time: Επίσημες Μεταφράσεις Φατριών',
      content: `# Athens Through Time: Επίσημες Μεταφράσεις Φατριών

Στο χρονικό **Athens Through Time**, οι επίσημες μεταφράσεις των 13 φατριών του **Vampire: The Masquerade** καθορίζουν τα ιστορικά προσωνύμια και τις αποδόσεις των οικογενειών στην ελληνική γλώσσα.

## Πίνακας Επίσημων Μεταφράσεων

| Έμβλημα | Φατρία | Επίσημη Μετάφραση | Σύνδεσμος |
| :---: | :--- | :--- | :--- |
| :Ventrue: | **[[Ventrue]]** | **Τύραννοι** | [[Ventrue|Άρθρο Ventrue]] |
| :Toreador: | **[[Toreador]]** | **Ταυροκαθρέπτες** | [[Toreador|Άρθρο Toreador]] |
| :Nosferatu: | **[[Nosferatu]]** | **Νοσοφόροι** | [[Nosferatu|Άρθρο Nosferatu]] |
| :Lasombra: | **[[Lasombra]]** | **Επίσκιοι** | [[Lasombra|Άρθρο Lasombra]] |
| :Tremere: | **[[Tremere]]** | **Τριμερείς** | [[Tremere|Άρθρο Tremere]] |
| :Brujah: | **[[Brujah]]** | **Βρούχοι** | [[Brujah|Άρθρο Brujah]] |
| :Ravnos: | **[[Ravnos]]** | **Ράβνος** | [[Ravnos|Άρθρο Ravnos]] |
| :Banu_Haqim: | **[[Banu_Haqim]]** | **Τέκνα του Χακίμ / Χακιμίτες / Ασσαμίτες** | [[Banu_Haqim|Άρθρο Banu Haqim]] |
| :Hecata: | **[[Hecata]]** | **Αικαταίοι** | [[Hecata|Άρθρο Hecata]] |
| :Malkavian: | **[[Malkavian]]** | **Μαινάδες** | [[Malkavian|Άρθρο Malkavian]] |
| :Tzimisce: | **[[Tzimisce]]** | **Τσιμισκήδες** | [[Tzimisce|Άρθρο Tzimisce]] |
| :Gangrel: | **[[Gangrel]]** | **Λυκάονες** | [[Gangrel|Άρθρο Gangrel]] |
| :Ministry: | **[[The_Ministry]]** | **Ιερατείο / Σετίτες** | [[The_Ministry|Άρθρο The Ministry]] |
| :Salubri: | **[[Salubri]]** | **Σαλούμπρι / Προφήτες** | [[Salubri|Άρθρο Salubri]] |

## Αναλυτική Παρουσίαση Φατριών

### Ventrue (Τύραννοι)
:Ventrue: **[[Ventrue]]**
Οι **[[Ventrue]]**, γνωστοί στην Αθήνα ως **Τύραννοι**, κρατούν σταθερά τα σκήπτρα της εξουσίας και της Καμαρίλα. Επιβάλλουν την τάξη και την ιεραρχία, θεωρώντας το δικαίωμα της ηγεμονίας αναφαίρετη κληρονομιά του αίματός τους.

### Toreador (Ταυροκαθρέπτες)
:Toreador: **[[Toreador]]**
Οι **[[Toreador]]**, οι **Ταυροκαθρέπτες**, εμπνέονται από την αρχαία μινωική και κλασική τέχνη των ταυροκαθαρψίων και την αντανάκλαση του κάλλους. Κυριαρχούν στα Ελύσια και στους χώρους τέχνης και πολιτισμού της Αθήνας.

### Nosferatu (Νοσοφόροι)
:Nosferatu: **[[Nosferatu]]**
Οι **[[Nosferatu]]**, οι **Νοσοφόροι**, κινούνται στα κατακόμβια δίκτυα και στους υπονόμους της πόλης. Παρά την παραμόρφωση και το στίγμα της κατάρας τους, αποτελούν τους πιο αλάνθαστους συλλέκτες πληροφοριών και κατασκόπους.

### Lasombra (Επίσκιοι)
:Lasombra: **[[Lasombra]]**
Οι **[[Lasombra]]**, οι σκοτεινοί άρχοντες που ιστορικά κυριάρχησαν στις σκιές της Μεσογείου, φέρουν το προσωνύμιο **Επίσκιοι**. Χειραγωγούν το αρχέγονο σκοτάδι της Αβύσσου και τις σκιές των παρασκηνίων.

### Tremere (Τριμερείς)
:Tremere: **[[Tremere]]**
Οι **[[Tremere]]**, οι μάγοι του Αίματος, αναφέρονται ως **Τριμερείς** λόγω της τριαδικής και ερμητικής τους δομής και των μυστικιστικών τους ιεραρχιών. Η Μαγεία του Αίματος (Blood Sorcery) είναι το απόλυτο όπλο τους.

### Brujah (Βρούχοι)
:Brujah: **[[Brujah]]**
Οι **[[Brujah]]**, οι **Βρούχοι**, φέρουν τις ρίζες τους από την εποχή των φιλοσόφων και των επαναστατών της κλασικής Αθήνας. Παθιασμένοι μαχητές και ιδεολόγοι, βρίσκονται συχνά στην πρωτοπορία των Ανάρχων.

### Ravnos (Ράβνος)
:Ravnos: **[[Ravnos]]**
Οι **[[Ravnos]]**, οι περιπλανώμενοι μάστορες των ψευδαισθήσεων και της εξαπάτησης, κινούνται χωρίς μόνιμη έδρα, διατηρώντας το αρχαίο όνομα **Ράβνος**.

### Banu Haqim (Τέκνα του Χακίμ)
:Banu_Haqim: **[[Banu_Haqim]]**
Οι **[[Banu_Haqim]]**, γνωστοί ιστορικά ως **Τέκνα του Χακίμ**, **Χακιμίτες** ή **Ασσαμίτες**, λειτουργούν ως δικαστές, τιμωροί και αθόρυβοι εκτελεστές.

### Hecata (Αικαταίοι)
:Hecata: **[[Hecata]]**
Οι **[[Hecata]]**, οι νεκρομάντεις της Εκάτης, φέρουν το όνομα **Αικαταίοι**. Ελέγχουν τα σύνορα ανάμεσα στους ζωντανούς, τους νεκρούς και τους απέθαντους, ενοποιώντας τις οικογένειες του Θανάτου.

### Malkavian (Μαινάδες)
:Malkavian: **[[Malkavian]]**
Οι **[[Malkavian]]**, οι διορατικοί αλλά καταραμένοι με παράνοια, ονομάζονται **Μαινάδες** προς τιμήν της διονυσιακής μανίας και της θεϊκής έκστασης που αποκαλύπτει κρυμμένες αλήθειες.

### Tzimisce (Τσιμισκήδες)
:Tzimisce: **[[Tzimisce]]**
Οι **[[Tzimisce]]**, οι πλάστες της σάρκας και της γης, φέρουν το βυζαντινό όνομα **Τσιμισκήδες**, άρχοντες παλαιών ηγεμονιών και κτητόρων της γης.

### Gangrel (Λυκάονες)
:Gangrel: **[[Gangrel]]**
Οι **[[Gangrel]]**, οι πρωτόγονοι κυνηγοί της ερημιάς και της άγριας φύσης, αποκαλούνται **Λυκάονες** από τον αρχαίο μύθο του Λυκάονα, έχοντας βαθιά επαφή με το Κτήνος.

### The Ministry (Ιερατείο / Σετίτες)
:Ministry: **[[The_Ministry]]**
Οι **[[The_Ministry]]**, ιστορικά γνωστοί ως **Σετίτες** και πλέον ως **Ιερατείο**, αποτελούν τους δελεαστές και πνευματικούς δηλητηριαστές που γκρεμίζουν τις ηθικές αναστολές.

### Salubri (Σαλούμπρι / Προφήτες)
:Salubri: **[[Salubri]]**
Οι **[[Salubri]]**, οι σπάνιοι και διωκόμενοι θεραπευτές και μυστικιστές, αναφέρονται ως **Σαλούμπρι** ή **Προφήτες**, διατηρώντας το τρίτο μάτι και την αναζήτηση της Γκολκόντα.

## Χρήση Εμβλημάτων στο Wiki

Μπορείτε να εισάγετε τα εμβλήματα των φατριών σε οποιοδήποτε άρθρο χρησιμοποιώντας σύνταξη emoji όπως στο chat:
* \`:Ventrue:\` ή \`:Τύραννοι:\`
* \`:Toreador:\` ή \`:Ταυροκαθρέπτες:\`
* \`:Nosferatu:\` ή \`:Νοσοφόροι:\`
* \`:Lasombra:\` ή \`:Επίσκιοι:\`
* \`:Tremere:\` ή \`:Τριμερείς:\`
* \`:Brujah:\` ή \`:Βρούχοι:\`
* \`:Ravnos:\` ή \`:Ράβνος:\`
* \`:Banu_Haqim:\` ή \`:Χακιμίτες:\`
* \`:Hecata:\` ή \`:Αικαταίοι:\`
* \`:Malkavian:\` ή \`:Μαινάδες:\`
* \`:Tzimisce:\` ή \`:Τσιμισκήδες:\`
* \`:Gangrel:\` ή \`:Λυκάονες:\`
* \`:Ministry:\` ή \`:Ιερατείο:\`
* \`:Salubri:\` ή \`:Σαλούμπρι:\`

Κάθε έμβλημα λειτουργεί ταυτόχρονα και ως αυτόματος υπερσύνδεσμος προς το άρθρο της αντίστοιχης φατρίας.`
    },
    {
      slug: 'Ventrue',
      title: 'Clan Ventrue (Τύραννοι)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Ventrue_symbol_white.webp","caption":"Έμβλημα των Ventrue","fields":[{"key":"Φατρία","value":"Ventrue"},{"key":"Επίσημη Μετάφραση","value":"Τύραννοι"},{"key":"Nicknames","value":"The Clan of Kings, Blue Bloods, Tyrants, Patricians, Borgias"},{"key":"Παράταξη","value":"Camarilla"},{"key":"Disciplines","value":"Dominate, Fortitude, Presence"},{"key":"Bane","value":"Rarefied Taste (Εκλεκτικό Γούστο)"},{"key":"Compulsion","value":"Leadership (Ηγεμονία)"}]}[/INFOBOX]

# Clan Ventrue (Τύραννοι)

:Ventrue: **[[Ventrue]]**

## Overview
The Ventrue are not called the Clan of Kings for nothing. Carefully choosing their progeny from mortals familiar with power, wealth, and influence, the Ventrue style themselves the aristocrats of the vampire world. Their members are expected to assume command wherever possible, and they are willing to endure storms for the sake of leading from the front.

To them, they are the rightful heirs of power and command. The Ventrue have held more positions of power than any other clan: as god kings in ancient Babylon to majority shareholders and campaign fund backers in the modern age, they have held their footing as long as they could. Though in recent nights their status has begun to slip, many Ventrue feel their time is running out and as their privileges slip through their fingers, most Ventrue tighten their grasp, willing to fight fang and claw to keep hold.

## Disciplines
* **Dominate:** The ability to bend the minds and wills of mortals and vampires to their absolute command.
* **Fortitude:** Supernatural resilience and endurance allowing them to withstand physical and supernatural assault.
* **Presence:** The power to instill awe, terror, or magnetic devotion in crowds and individuals.

## Bane and Compulsion
* **Κατάρα (Bane: Rarefied Taste):** Οι Ventrue διαθέτουν εξαιρετικά εκλεκτικό ουρανίσκο. Μπορούν να τραφούν αποκλειστικά από συγκεκριμένο τύπο θνητών (όπως άτομα συγκεκριμένης καταγωγής, επαγγέλματος ή ψυχολογικής διάθεσης). Οποιοδήποτε άλλο αίμα προκαλεί άμεση απόρριψη.
* **Παρόρμηση (Compulsion: Leadership):** Η ανάγκη για εξουσία κατακλύζει το μυαλό τους. Πρέπει να πάρουν τον έλεγχο της κατάστασης και να επιβάλλουν τις εντολές τους σε όλους γύρω τους.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Ventrue** φέρουν επίσημα το ιστορικό προσωνύμιο **Τύραννοι**. Αντλώντας κύρος από τις αρχαίες αθηναϊκές ηγεμονίες, αποτελούν τον πυλώνα της τοπικής Καμαρίλα και των παραδοσιακών θεσμών εξουσίας.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Toreador',
      title: 'Clan Toreador (Ταυροκαθρέπτες)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Toreador_symbol_white.webp","caption":"Έμβλημα των Toreador","fields":[{"key":"Φατρία","value":"Toreador"},{"key":"Επίσημη Μετάφραση","value":"Ταυροκαθρέπτες"},{"key":"Nicknames","value":"The Clan of Divas, Degenerates, Artists, Hedonists, Sensates"},{"key":"Παράταξη","value":"Camarilla"},{"key":"Disciplines","value":"Auspex, Celerity, Presence"},{"key":"Bane","value":"Aesthetic Fixation (Αισθητική Καθήλωση)"},{"key":"Compulsion","value":"Obsession (Εμμονή)"}]}[/INFOBOX]

# Clan Toreador (Ταυροκαθρέπτες)

:Toreador: **[[Toreador]]**

## Overview
Known for their seductive nature, enthralling demeanor, and eloquent grace to the point of obsession, Toreador vampires Embrace artists and lovers into their ranks, forever trying to stir their own deadened hearts. Supernaturally graceful and charming, the Divas are always looking for the next thrill, leaving a detritus of discarded lovers and victims in their wake.

A clan who exudes beauty, one who seeks out the aesthetics in life and holds their obsessions with it. However, it is a mistake to think of them as nothing but Divas. Beauty is power and the way they utilize love to influence those around them to do just about anything is an invaluable weapon. The elders of their clan stress that the Embrace must be given to those worthy and that the clan seeks out pioneers of different arts. The clan prospers when filled with fresh ideas and creators who value experimentation and discovery of new aesthetics.

## Disciplines
* **Auspex:** Heightened senses and psychic perception, enabling them to read auras and uncover hidden truths.
* **Celerity:** Unnatural speed and grace, moving with breathtaking rapidity.
* **Presence:** Magnetism and raw emotional allure that draws mortals and vampires under their thrall.

## Bane and Compulsion
* **Κατάρα (Bane: Aesthetic Fixation):** Παγιδεύονται στη θέα του απόλυτου κάλλους ή της ακραίας ασχήμιας. Όταν αντικρίζουν κάτι αισθητικά καθηλωτικό, αδυνατούν να αποσπάσουν το βλέμμα τους και δυσκολεύονται να αντιδράσουν στο περιβάλλον.
* **Παρόρμηση (Compulsion: Obsession):** Κυριεύονται από εμμονή για ένα πρόσωπο, έργο τέχνης ή ιδέα, αγνοώντας οποιαδήποτε άλλη προτεραιότητα.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Toreador** αποκαλούνται **Ταυροκαθρέπτες**, αντλώντας έμπνευση από τα μινωικά ταυροκαθάρψια και την αντανάκλαση του κάλλους στους καθρέπτες των Ελυσίων.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Nosferatu',
      title: 'Clan Nosferatu (Νοσοφόροι)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Nosferatu_symbol_white.webp","caption":"Έμβλημα των Nosferatu","fields":[{"key":"Φατρία","value":"Nosferatu"},{"key":"Επίσημη Μετάφραση","value":"Νοσοφόροι"},{"key":"Nicknames","value":"The Clan of the Hidden, Horrors, Sewer Rats, Lepers, Orloks"},{"key":"Παράταξη","value":"Camarilla"},{"key":"Disciplines","value":"Animalism, Obfuscate, Potence"},{"key":"Bane","value":"Repulsive Appearance (Αποτρόπαια Όψη)"},{"key":"Compulsion","value":"Cryptophilia (Κρυπτοφιλία)"}]}[/INFOBOX]

# Clan Nosferatu (Νοσοφόροι)

:Nosferatu: **[[Nosferatu]]**

## Overview
The Nosferatu wear their curse on the outside. Their bodies horribly twisted and deformed through the Embrace, they lurk on the fringes of most cities, acting as spies and brokers of information. Using animals and their own supernatural capacity to hide, nothing escapes the eyes of the so called Sewer Rats.

Their Embrace is one of the most painful, twisting and deforming their body into something monstrous. The entire transformation process can take weeks and result in deformities similar to growths, sores, or severe injuries. Regardless of their appearance, they are often some of the most compassionate kindred from wearing their curse on the outside rather than inside. To blend in some will use their abilities within Obfuscate or heavy prosthetics, moving through tunnels and catacombs to report safely.

## Disciplines
* **Animalism:** Supernatural mastery over vermin and subterranean creatures, turning beasts into eyes and ears.
* **Obfuscate:** The mystical art of vanishing from mortal and kindred perception through mental misdirection.
* **Potence:** Raw, terrifying physical strength that allows them to shatter stone and iron with ease.

## Bane and Compulsion
* **Κατάρα (Bane: Repulsive Appearance):** Το Αγκάλιασμα παραμορφώνει ανεπανόρθωτα τη μορφή τους. Η αποκάλυψη του πραγματικού τους προσώπου σε θνητούς παραβιάζει αυτόματα την Μασκαράντα.
* **Παρόρμηση (Compulsion: Cryptophilia):** Ακατανίκητη δίψα για μυστικά. Πρέπει να αποσπάσουν, να αποκρύψουν ή να αποκτήσουν πρόσβαση σε κρυφές πληροφορίες.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Nosferatu** αναφέρονται επίσημα ως **Νοσοφόροι**. Κυριαρχούν στα υπόγεια δίκτυα της αρχαίας και σύγχρονης Αθήνας, ελέγχοντας τα μυστικά της πόλης.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Lasombra',
      title: 'Clan Lasombra (Επίσκιοι)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Lasombra_symbol_white.webp","caption":"Έμβλημα των Lasombra","fields":[{"key":"Φατρία","value":"Lasombra"},{"key":"Επίσημη Μετάφραση","value":"Επίσκιοι"},{"key":"Nicknames","value":"The Night Clan, Magisters, Keepers, Shadows, Abyss Mystics"},{"key":"Παράταξη","value":"Camarilla"},{"key":"Disciplines","value":"Dominate, Oblivion, Potence"},{"key":"Bane","value":"Distorted Image (Άμορφο Είδωλο)"},{"key":"Compulsion","value":"Ruthlessness (Ανηλεότητα)"}]}[/INFOBOX]

# Clan Lasombra (Επίσκιοι)

:Lasombra: **[[Lasombra]]**

## Overview
Creatures subtly at odds with mundane reality, Lasombra vampires are expected to triumph at any cost. Ruthlessness is a sought after trait in progeny, making their reputation as betraying interlopers well deserved. Most do not seek attention, preferring to act as puppeteers, powers behind the proverbial throne. To a Shadow, the ends justify any means.

The Lasombra rarely have time for the weak, with a perspective that the only way to survive is to excel. Sympathy and morality do nothing but weigh them down and prevent their inevitable climb to power. They generally Embrace those who fought against the odds and came out on top, those who survive dangerous situations or otherwise exemplify excellence. The Magisters also tend to lean into institutions and religion to find candidates who understand organizational discipline and command.

## Disciplines
* **Dominate:** Cold, unyielding psychic mastery over mortal and kindred wills.
* **Oblivion:** Channeling the primordial darkness of the Abyss, manipulating shadows and the cold void.
* **Potence:** Devastating physical force that crushes opposition without mercy.

## Bane and Compulsion
* **Κατάρα (Bane: Distorted Image):** Δεν έχουν καθαρό είδωλο σε καθρέπτες ή ανακλαστικές επιφάνειες, ενώ κάμερες, μικρόφωνα και ηλεκτρονικές συσκευές παρουσιάζουν παράσιτα και παραμορφώσεις παρουσία τους.
* **Παρόρμηση (Compulsion: Ruthlessness):** Η αποτυχία είναι ανεπίτρεπτη. Πρέπει να πετύχουν τον στόχο τους με κάθε κόστος, συνθλίβοντας οποιαδήποτε εσωτερική ή εξωτερική αμφιβολία.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Lasombra** αναγνωρίζονται ως **Επίσκιοι**. Χειραγωγούν το παρασκήνιο της εξουσίας, διατηρώντας ισχυρή επιρροή στους εκκλησιαστικούς και πολιτικούς μηχανισμούς.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Tremere',
      title: 'Clan Tremere (Τριμερείς)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Tremere_symbol_white.webp","caption":"Έμβλημα των Tremere","fields":[{"key":"Φατρία","value":"Tremere"},{"key":"Επίσημη Μετάφραση","value":"Τριμερείς"},{"key":"Nicknames","value":"The Broken Clan, Usurpers, Warlocks, Hermetics, Blood Mages"},{"key":"Παράταξη","value":"Camarilla"},{"key":"Disciplines","value":"Auspex, Blood Sorcery, Dominate"},{"key":"Bane","value":"Deficient Bond (Εξασθενημένος Δεσμός)"},{"key":"Compulsion","value":"Perfectionism (Τελειομανία)"}]}[/INFOBOX]

# Clan Tremere (Τριμερείς)

:Tremere: **[[Tremere]]**

## Overview
The arcane Clan Tremere were once a house of mortal mages who sought immortality but found only undeath. As vampires, they have perfected ways to bend their own Blood to their will, employing their sorceries to master both the mortal and vampire world. Their power makes them valuable, but few vampires trust their scheming ways.

Tremere was once the name of an eighth century Romanian hermetic mage, obsessed with knowledge and power. This obsession allowed him to prolong his lifespan beyond the mortal timeframe, but eventually his power weakened. Instigating mystical experiments with kindred vitae, Tremere and his inner circle underwent the transformation into the undead. Developing Blood Sorcery to replicate their lost hermetic magic, they organized their clan into the Pyramid, an imposing occult hierarchy.

## Disciplines
* **Auspex:** Clairvoyance, astral perception, and detection of mystical energies.
* **Blood Sorcery:** The transmutation and weaponization of vitae through rituals, alchemy, and thaumaturgical strikes.
* **Dominate:** Mental hypnosis and subtle reprogramming of human and kindred minds.

## Bane and Compulsion
* **Κατάρα (Bane: Deficient Bond):** Μετά την καταστροφή της Μεγάλης Συντεχνίας στη Βιέννη, οι Tremere αδυνατούν να δέσουν με Δεσμό Αίματος άλλους βρικόλακες, ενώ απαιτούνται περισσότερες γουλιές για να δέσουν θνητούς.
* **Παρόρμηση (Compulsion: Perfectionism):** Απαιτούν απόλυτη, μαθηματική τελειότητα σε κάθε τελετουργία ή πράξη, αρνούμενοι να προχωρήσουν αν κάτι δεν είναι αψεγάδιαστο.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Tremere** φέρουν το όνομα **Τριμερείς**, αντανακλώντας την ερμητική και τριαδική τους δομή. Αποτελούν τους θεματοφύλακες της απόκρυφης γνώσης στην Αθήνα.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Brujah',
      title: 'Clan Brujah (Βρούχοι)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Brujah_symbol_white.webp","caption":"Έμβλημα των Brujah","fields":[{"key":"Φατρία","value":"Brujah"},{"key":"Επίσημη Μετάφραση","value":"Βρούχοι"},{"key":"Nicknames","value":"The Learned Clan, Rabble, Punks, Rebels, Philosopher Kings, Hellenes"},{"key":"Παράταξη","value":"Anarch"},{"key":"Disciplines","value":"Celerity, Potence, Presence"},{"key":"Bane","value":"Violent Temper (Έντονη Οργή)"},{"key":"Compulsion","value":"Rebellion (Επανάσταση)"}]}[/INFOBOX]

# Clan Brujah (Βρούχοι)

:Brujah: **[[Brujah]]**

## Overview
The Brujah are a clan of radicals and troublemakers, Embracing those willing to put someone in their place if the situation calls for it. Most see themselves as warriors with a cause, and these Rebels are guided by their passions, strength, and dedication to their ideals.

Brujah are generally Embraced from the ranks of those who are sympathetic to those who do not back down, seeking out others who question the status quo and welcome countercultures. From spirited fighters to critical thinkers, the clan is bolstered by their ability to withstand the storm and persevere through hardships. The Brujah are commonly misplaced as mere street punks, but their heritage is steeped in the ancient tradition of philosopher kings and classical Hellenic democracy.

## Disciplines
* **Celerity:** Explosive supernatural speed in combat and movement.
* **Potence:** Crushing physical might capable of tearing steel and overturning vehicles.
* **Presence:** Inspiring or intimidating crowds, igniting revolutionary passion.

## Bane and Compulsion
* **Κατάρα (Bane: Violent Temper):** Έντονη ροπή προς την οργή και το Φρενίτιδα. Οι Brujah δυσκολεύονται εξαιρετικά να συγκρατήσουν το Κτήνος όταν προκαλούνται ή προσβάλλονται.
* **Παρόρμηση (Compulsion: Rebellion):** Άρνηση υποταγής σε οποιαδήποτε εξουσία ή εντολή, αντιδρώντας επιθετικά σε κάθε μορφή εξαναγκασμού.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Brujah** αποκαλούνται **Βρούχοι**. Με ρίζες που ανάγονται στην Ακαδημία και την Αγορά της αρχαίας πόλης, ηγούνται του κινήματος των Ανάρχων στην πρωτεύουσα.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Ravnos',
      title: 'Clan Ravnos (Ράβνος)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Ravnos_symbol_white.webp","caption":"Έμβλημα των Ravnos","fields":[{"key":"Φατρία","value":"Ravnos"},{"key":"Επίσημη Μετάφραση","value":"Ράβνος"},{"key":"Nicknames","value":"Rogues, Ravens, Daredevils, The Haunted, Tricksters"},{"key":"Παράταξη","value":"Independent / Unaligned"},{"key":"Disciplines","value":"Animalism, Obfuscate, Presence"},{"key":"Bane","value":"Doomed (Ανήσυχο Πνεύμα)"},{"key":"Compulsion","value":"Daredevil (Ριψοκίνδυνος)"}]}[/INFOBOX]

# Clan Ravnos (Ράβνος)

:Ravnos: **[[Ravnos]]**

## Overview
Masters of misdirection, the Ravnos prefer not to fight or bleed for something they can obtain through subtler means. They can charm and vanish within the same mortal breath, and those once fooled quickly learn to question their very senses when in the company of Ravens. Always on the move, the Ravnos can never rest in the same place for long lest their curse light them on fire as they slumber.

They were almost annihilated during the beginning act of the Gehenna War during the Week of Nightmares, but with time the clan is growing stronger once more. Most Ravnos rely on their wits, clever charm, and illusions. They prefer not to bleed when able, using subtle methods to obtain whatever it is they desire. For this reason it is rare they make their true nature known and once they have, they disappear into the night as quickly as they appeared.

## Disciplines
* **Animalism:** Communion with ravens, foxes, and wandering scavengers.
* **Obfuscate:** Illusions, phantasms, and seamless sensory deception.
* **Presence:** Fascinating and disarming witnesses with hypnotic charm.

## Bane and Compulsion
* **Κατάρα (Bane: Doomed):** Το αίμα τους κουβαλά μια αρχαία κατάρα φωτιάς. Δεν μπορούν να αναπαυθούν στο ίδιο σημείο για διαδοχικές νύχτες, αλλιώς ο ήλιος καίει το σώμα τους κατά τη διάρκεια της ημέρας.
* **Παρόρμηση (Compulsion: Daredevil):** Ακατανίκητη τάση για επικίνδυνα ρίσκα και τολμηρά σχέδια χωρίς δισταγμό.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Ravnos** διατηρούν το όνομα **Ράβνος**. Κινούνται διαρκώς στα λιμάνια και στις οδικές αρτηρίες της Αττικής, αρνούμενοι να εγκατασταθούν μόνιμα.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Banu_Haqim',
      title: 'Clan Banu Haqim (Τέκνα του Χακίμ)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Banu_Haqim_symbol_white.webp","caption":"Έμβλημα των Banu Haqim","fields":[{"key":"Φατρία","value":"Banu Haqim"},{"key":"Επίσημη Μετάφραση","value":"Τέκνα του Χακίμ / Χακιμίτες / Ασσαμίτες"},{"key":"Nicknames","value":"Clan of the Hunt, Assassins, Children of Haqim, Saracens, Lawmen, Judges"},{"key":"Παράταξη","value":"Camarilla"},{"key":"Disciplines","value":"Blood Sorcery, Celerity, Obfuscate"},{"key":"Bane","value":"Blood Addiction (Εθισμός στο Αίμα)"},{"key":"Compulsion","value":"Judgment (Κρίση)"}]}[/INFOBOX]

# Clan Banu Haqim (Τέκνα του Χακίμ)

:Banu_Haqim: **[[Banu_Haqim]]**

## Overview
The Judges of the Banu Haqim are torn between their hereditary thirst for vampiric Blood and their passion for justice. Stern adjudicators, they are fiercely devoted to upholding a moral code, and Embrace mortals capable of assessing and handling threats, enforcing laws and traditions, and punishing transgressors.

Regardless of the individual Banu Haqim's stance, they all adhere to some type of strict code, be it blood laws, personal ethics, governmental or religious rules. The Banu Haqim's instinct to find the guilty is intrinsic to the Blood: those guilty of whatever transgression a Child of Haqim deems unforgivable must be punished, and punishment might even include taking unlife from their veins. They hail from all over the world, representing various beliefs united under the legacy of Alamut and the laws of the Camarilla.

## Disciplines
* **Blood Sorcery:** Quietus sorcery, transmuting blood into acidic toxins and silent blades.
* **Celerity:** Lethal, instantaneous speed for swift executions.
* **Obfuscate:** Moving unseen through shadows and crowds.

## Bane and Compulsion
* **Κατάρα (Bane: Blood Addiction):** Εθισμός στο αίμα άλλων βρικολάκων. Όταν πίνουν βρυκολακικό αίμα, κινδυνεύουν να υποστούν Φρενίτιδα Δίψας και να διαπράξουν Διαβολισμό.
* **Παρόρμηση (Compulsion: Judgment):** Υποχρέωση να κρίνουν και να τιμωρήσουν όποιον παραβιάζει τους νόμους ή τις ηθικές αρχές.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Banu Haqim** αναφέρονται ως **Τέκνα του Χακίμ**, **Χακιμίτες** ή **Ασσαμίτες**, λειτουργώντας ως αδέκαστοι δικαστές και εκτελεστές στην υπηρεσία των νόμων.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Hecata',
      title: 'Clan Hecata (Αικαταίοι)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Hecata_symbol_white.webp","caption":"Έμβλημα των Hecata","fields":[{"key":"Φατρία","value":"Hecata"},{"key":"Επίσημη Μετάφραση","value":"Αικαταίοι"},{"key":"Nicknames","value":"The Clan of Death, Necromancers, Graverobbers, The Family, Lazarenes"},{"key":"Παράταξη","value":"Independent"},{"key":"Disciplines","value":"Auspex, Fortitude, Oblivion"},{"key":"Bane","value":"Painful Bite (Επώδυνο Δάγκωμα)"},{"key":"Compulsion","value":"Morbidity (Νοσηρότητα)"}]}[/INFOBOX]

# Clan Hecata (Αικαταίοι)

:Hecata: **[[Hecata]]**

## Overview
A motley collection of necromantic vampire bloodlines, the Hecata clan are united in the pursuit of a single subject: Death. They are students of the afterlife and resurrectionists of the dead: or worse. Selling their services to the highest bidder, or acting in their own interests, there are few who can hide from the surveillance of those who can summon and command the very spirits of the deceased.

A clan steeped in death, they practice the arts of necromancy and communication with the dead. The clan tends to favour mortals either from their own mortal family or those with useful connections to other outside lineages. Following the Family Reunion, the Giovanni, Cappadocians, Samedi, Harbingers, and Nagaraja unified under the banner of Hecata, sharing common mastery over the realm of the grave.

## Disciplines
* **Auspex:** Seeing ghosts, reading spirits, and sensing deaths in the vicinity.
* **Fortitude:** The cold endurance of the grave, resisting physical and mystical harm.
* **Oblivion:** Necromancy, summoning wraiths, commanding shadows, and decaying mortal matter.

## Bane and Compulsion
* **Κατάρα (Bane: Painful Bite):** Το δάγκωμά τους δεν προσφέρει καμία ευχαρίστηση ή έκσταση. Προκαλεί φριχτό, αφόρητο πόνο στο θύμα, καθιστώντας το κυνήγι επικίνδυνο.
* **Παρόρμηση (Compulsion: Morbidity):** Εμμονή με τον θάνατο, τα πτώματα και τα μυστήρια του Κάτω Κόσμου.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Hecata** αποκαλούνται επίσημα **Αικαταίοι**, όνομα συνδεδεμένο με την αρχαία θεά Εκάτη, φύλακα των σταυροδρομιών και του Κάτω Κόσμου.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Malkavian',
      title: 'Clan Malkavian (Μαινάδες)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Malkavian_symbol_white.webp","caption":"Έμβλημα των Malkavian","fields":[{"key":"Φατρία","value":"Malkavian"},{"key":"Επίσημη Μετάφραση","value":"Μαινάδες"},{"key":"Nicknames","value":"The Clan of the Moon, Lunatics, Oracles, Dervishes, Visionaries, Children of Malkav"},{"key":"Παράταξη","value":"Camarilla"},{"key":"Disciplines","value":"Auspex, Dominate, Obfuscate"},{"key":"Bane","value":"Fractured Mind (Αθεράπευτη Παράνοια)"},{"key":"Compulsion","value":"Delusion (Παραίσθηση)"}]}[/INFOBOX]

# Clan Malkavian (Μαινάδες)

:Malkavian: **[[Malkavian]]**

## Overview
Derided as Lunatics by other vampires, the Blood of the Malkavian clan lets them perceive and foretell truths hidden from others. Like the wise madmen of poetry their fractured perspective stems from seeing too much of the world at once, from understanding too deeply, and feeling emotions that are just too strong to bear.

Their Embraces come from all walks of life and age, often seeking the Second Sight: the ability to understand dreams, perceive spirits or predict the future. All Children of Malkav share a connection through a collective subconscious link known as the Cobweb or the Network, an invisible psychic wavelength connecting their minds across time and distance.

## Disciplines
* **Auspex:** Precognition, telepathy, and piercing the veil of mortal reality.
* **Dominate:** Dementation: projecting mental fractures and hallucinations directly into the minds of others.
* **Obfuscate:** Fading from conscious sight and blending into the background of perceptions.

## Bane and Compulsion
* **Κατάρα (Bane: Fractured Mind):** Κάθε Malkavian υποφέρει από ανίατη ψυχική διαταραχή ή παράνοια που δεν μπορεί να θεραπευτεί με οποιοδήποτε μέσο.
* **Παρόρμηση (Compulsion: Delusion):** Βυθίζονται σε παραισθήσεις ή οράματα, ερμηνεύοντας την πραγματικότητα μέσα από σουρεαλιστικά σύμβολα.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Malkavian** αποκαλούνται **Μαινάδες** προς τιμήν της αρχαίας διονυσιακής έκστασης και θεϊκής μανίας που αποκαλύπτει κρυμμένες αλήθειες.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Tzimisce',
      title: 'Clan Tzimisce (Τσιμισκήδες)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Tzimisce_symbol_white.webp","caption":"Έμβλημα των Tzimisce","fields":[{"key":"Φατρία","value":"Tzimisce"},{"key":"Επίσημη Μετάφραση","value":"Τσιμισκήδες"},{"key":"Nicknames","value":"Dragons, The Old Clan, Voivodes, Stokers, Fleshcrafters"},{"key":"Παράταξη","value":"Anarch / Sabbat / Independent"},{"key":"Disciplines","value":"Animalism, Dominate, Protean"},{"key":"Bane","value":"Grounded (Δεσμός με τη Γη)"},{"key":"Compulsion","value":"Covetousness (Κτητικότητα)"}]}[/INFOBOX]

# Clan Tzimisce (Τσιμισκήδες)

:Tzimisce: **[[Tzimisce]]**

## Overview
The dragons view ownership above all: they aim to conquer and rule the subject of their possessiveness. Traditionally their charges were based on geographical locations, hence the stereotype of a vampire in a looming castle. However, in the modern age, younger generations have taken a more flexible approach, staking claim over mortals, gangs, or domains rather than physical castles.

These possessive traits extend beyond territory and into their own bodies. Many dragons specialize in Vicissitude, sculpting flesh and bone as clay to alter their bodies or reshape others into horrific art forms, pushing past the metaphysical limits of vampirism itself.

## Disciplines
* **Animalism:** Commanding beasts and guarding ancestral lands with savage predators.
* **Dominate:** Imposing their tyrannical will upon those residing within their territory.
* **Protean:** Vicissitude and physical metamorphosis, restructuring bone and flesh at will.

## Bane and Compulsion
* **Κατάρα (Bane: Grounded):** Πρέπει να κοιμούνται περιτριγυρισμένοι από χώμα της προγονικής τους γης ή από γη σημαντική για την ύπαρξή τους.
* **Παρόρμηση (Compulsion: Covetousness):** Ακατανίκητη ανάγκη να επιβάλουν πλήρη ιδιοκτησία σε αντικείμενα, πρόσωπα ή περιοχές.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Tzimisce** φέρουν το βυζαντινό όνομα **Τσιμισκήδες**, άρχοντες παλαιών οχυρών και κτητόρων της γης.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Gangrel',
      title: 'Clan Gangrel (Λυκάονες)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Gangrel_symbol_white.webp","caption":"Έμβλημα των Gangrel","fields":[{"key":"Φατρία","value":"Gangrel"},{"key":"Επίσημη Μετάφραση","value":"Λυκάονες"},{"key":"Nicknames","value":"The Clan of the Beast, Animals, Ferals, Barbarians, Wolves, Outcasts"},{"key":"Παράταξη","value":"Anarch"},{"key":"Disciplines","value":"Animalism, Fortitude, Protean"},{"key":"Bane","value":"Beastly Features (Ζωικά Χαρακτηριστικά)"},{"key":"Compulsion","value":"Feral Impulse (Άγρια Παρόρμηση)"}]}[/INFOBOX]

# Clan Gangrel (Λυκάονες)

:Gangrel: **[[Gangrel]]**

## Overview
Often closer to beasts than other vampires, the Gangrel style themselves apex predators. These Ferals prowl the wilds as easily as the urban jungle, and no clan of vampires can match their ability to endure, survive, and thrive in any environment. Often fiercely territorial, their shapeshifting abilities even give the undead pause.

Gangrel are generally embraced from prospects who show the ability to survive and fight. Due to this their customs encourage rivalry without taking competition personally. They are usually the outcasts of Kindred society, learning to live in undesirable areas and yet thrive without bending the knee to a Prince or Baron.

## Disciplines
* **Animalism:** Speaking with predators, summoning swarms, and unleashing the Beast.
* **Fortitude:** Legendary stamina that shrugs off bullets, fire, and claws.
* **Protean:** Shapeshifting into wolves, bats, mist, or extending razor sharp claws.

## Bane and Compulsion
* **Κατάρα (Bane: Beastly Features):** Μετά από κάθε Φρενίτιδα, το σώμα τους αποκτά προσωρινά ζωικά χαρακτηριστικά (όπως λέπια, γούνες, νύχια, μάτια λύκου) που μειώνουν την κοινωνική τους επιρροή.
* **Παρόρμηση (Compulsion: Feral Impulse):** Υποχώρηση στα πρωτόγονα ένστικτα του ζώου, αναζητώντας τροφή, επιβίωση και επικράτεια.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Gangrel** αποκαλούνται **Λυκάονες** από τον αρχαίο μύθο του βασιλιά Λυκάονα, έχοντας βαθιά επαφή με τη φύση και τα βουνά της Αττικής.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'The_Ministry',
      title: 'Clan The Ministry (Ιερατείο / Σετίτες)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Ministry_symbol_white.webp","caption":"Έμβλημα του Ministry","fields":[{"key":"Φατρία","value":"The Ministry"},{"key":"Επίσημη Μετάφραση","value":"Ιερατείο / Σετίτες"},{"key":"Nicknames","value":"The Clan of Faith, Setites, Followers of Set, Serpents, Liberators"},{"key":"Παράταξη","value":"Anarch"},{"key":"Disciplines","value":"Obfuscate, Presence, Protean"},{"key":"Bane","value":"Abhorrent to Light (Ευαισθησία στο Φως)"},{"key":"Compulsion","value":"Transgression (Παραβίαση)"}]}[/INFOBOX]

# Clan The Ministry (Ιερατείο / Σετίτες)

:Ministry: **[[The_Ministry]]**

## Overview
The Ministry always has something to offer. This often cult like clan recruits those able to employ temptation as a weapon. They Embrace those with the will and means to sway, entrap, and ultimately liberate their targets from whatever they seek: the victim’s possessions, allegiance, or even faith. To the Serpents, everything has a price.

The clan was formerly known as the Followers of Set. For as much as a cult as they are a clan, the majority of their members adhere to a disruptive system of beliefs. Known as tricksters, tempters and liberators, they seek to tear down moral illusions and expose the true desires of mortals and vampires alike.

## Disciplines
* **Obfuscate:** Moving silently, hiding temptations, and appearing as trusted allies.
* **Presence:** Overwhelming allure, creating cults of personality and devotion.
* **Protean:** Morphing into serpent forms, liquefying flesh, and venomous strikes.

## Bane and Compulsion
* **Κατάρα (Bane: Abhorrent to Light):** Εξαιρετικά ευάλωτοι στο ηλιακό φως και το έντονο τεχνητό φως, δεχόμενοι αυξημένη ζημιά και πόνο.
* **Παρόρμηση (Compulsion: Transgression):** Ανάγκη να παρασύρουν άλλους στην παραβίαση των ηθικών τους αρχών και κανόνων.

## Athens Through Time
Στο χρονικό **Athens Through Time**, το **Ministry** είναι γνωστό ως **Ιερατείο** (και ιστορικά ως **Σετίτες**), λειτουργώντας στους χώρους της νύχτας και της πνευματικής χειραγώγησης.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    },
    {
      slug: 'Salubri',
      title: 'Clan Salubri (Σαλούμπρι / Προφήτες)',
      content: `[INFOBOX]{"image":"https://portal.attlarp.gr/img/clans/white/330px-Salubri_symbol_white.webp","caption":"Έμβλημα των Salubri","fields":[{"key":"Φατρία","value":"Salubri"},{"key":"Επίσημη Μετάφραση","value":"Σαλούμπρι / Προφήτες"},{"key":"Nicknames","value":"Cyclops, Soul Thieves, Dajjals, Saulot's Progeny, Healers, Watchers"},{"key":"Παράταξη","value":"Independent / Unaligned"},{"key":"Disciplines","value":"Auspex, Dominate, Fortitude"},{"key":"Bane","value":"Coveted Blood (Ποθητό Αίμα)"},{"key":"Compulsion","value":"Empathy (Ενσυναίσθηση)"}]}[/INFOBOX]

# Clan Salubri (Σαλούμπρι / Προφήτες)

:Salubri: **[[Salubri]]**

## Overview
Most of their kind lost to undead usurpers, the highly desirable Blood of the hunted Salubri is a prize to other vampires. This, and their reluctance to Embrace, makes them rare in the modern nights. They often recruit those on the edge of death, believing their curse can provide the worthy a second chance, and they count some of the most humane vampires among their ranks.

Once known for their wisdom and healing arts, the clan barely exists these nights. Their legacy is one of tragedy and a painful lesson of the eternal struggle. The choice of a childe for the Salubri is an intensely personal decision: choosing those with inquisitive behaviors and a drive to solve difficult moral struggles or heal the afflicted.

## Disciplines
* **Auspex:** Supernatural spiritual perception and uncovering the secrets of souls.
* **Dominate:** Calming frenzied minds and enforcing peaceful truces.
* **Fortitude:** Obeah and Valeren healing arts, shielding others and enduring grave wounds.

## Bane and Compulsion
* **Κατάρα (Bane: Coveted Blood):** Το αίμα τους είναι εξαιρετικά ποθητό και γλυκό σε άλλους βρικόλακες, προκαλώντας ανεξέλεγκτη δίψα σε όποιον το δοκιμάσει. Η χρήση των πειθαρχιών τους κάνει το τρίτο μάτι στο μέτωπό τους να δακρύζει αίμα.
* **Παρόρμηση (Compulsion: Empathy):** Ανάγκη να προσφέρουν ανακούφιση και βοήθεια σε όσους υποφέρουν, ακόμη και με κίνδυνο της δικής τους ασφάλειας.

## Athens Through Time
Στο χρονικό **Athens Through Time**, οι **Salubri** είναι σπάνιοι και απομονωμένοι, αναφερόμενοι ως **Προφήτες** ή **Θεραπευτές**.

Επιστροφή στο κεντρικό άρθρο: [[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]`
    }
  ];

  for (const art of articles) {
    await conn.query(
      `INSERT INTO wiki_articles (author_id, title, slug, content, status)
       VALUES (?, ?, ?, ?, 'published')
       ON DUPLICATE KEY UPDATE title = VALUES(title), content = VALUES(content), status = VALUES(status)`,
      [1, art.title, art.slug, art.content]
    );
  }

  // Update Main Page with link to the translations article
  const mainPageContent = `# Καλώς ήρθατε στο Erebus Wiki

Το επίσημο αρχείο lore, φατριών, ιστορικού και πινάκων του χρονικού **Athens Through Time**.

## Προτεινόμενο Άρθρο
:Ventrue: **[[Athens_Through_Time_Clan_Translations|Athens Through Time: Επίσημες Μεταφράσεις Φατριών]]**
Ανακαλύψτε τις επίσημες ελληνικές μεταφράσεις και τα προσωνύμια των 13 φατριών του Vampire: The Masquerade για το χρονικό Athens Through Time.

## Περιήγηση
Χρησιμοποιήστε την πλαϊνή στήλη για να εξερευνήσετε τα άρθρα, το διαδραστικό χρονολόγιο ή το γράφημα γνώσης (Lore Graph).`;

  await conn.query(
    `INSERT INTO wiki_articles (author_id, title, slug, content, status)
     VALUES (?, ?, ?, ?, 'published')
     ON DUPLICATE KEY UPDATE content = VALUES(content)`,
    [1, 'Main Page', 'Main_Page', mainPageContent]
  );

  log.ok('Wiki Clan articles seeded successfully');
}

async function initWikiDatabase() {
  if (!wikiPool) return;
  let conn;
  try {
    conn = await wikiPool.getConnection();
    await conn.query('SET FOREIGN_KEY_CHECKS = 0');
    for (const ddl of WIKI_TABLE_DDLS) {
      await conn.query(ddl);
    }
    await conn.query('SET FOREIGN_KEY_CHECKS = 1');
    log.ok('Wiki Database schema verified (all 14 tables ready).');

    await seedClanArticles(conn);
  } catch (err) {
    log.err('Failed to verify Wiki Database schema', { error: err.message });
  } finally {
    if (conn) conn.release();
  }
}

module.exports = { initWikiDatabase };
