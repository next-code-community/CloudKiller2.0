# CloudKiller Pro 3.0

![Banner](https://img.shields.io/badge/CloudKiller-Pro%203.0-brightgreen)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![WAF Bypass](https://img.shields.io/badge/WAF%20Bypass-Cloudflare%20%7C%20Akamai%20%7C%20AWS-orange)
![Version](https://img.shields.io/badge/Version-3.0.0-informational)
![Stars](https://img.shields.io/badge/Stars-★★★★★-yellow)
![Contributors](https://img.shields.io/badge/Contributors-12-blueviolet)

## Bypass Cloud Protection - Advanced Subdomain Discovery & Analysis Tool

CloudKiller Pro è uno strumento avanzato per la scoperta di sottodomini che bypassa le protezioni cloud comuni. Progettato per penetration tester, security researcher e professionisti della sicurezza, CloudKiller consente di scoprire asset nascosti o dimenticati che potrebbero rappresentare una superficie di attacco per la tua organizzazione.

![CloudKiller Screenshot](https://github.com/user-attachments/assets/ebd062b3-bbad-457b-810b-89629c419c46)


## 🚀 Caratteristiche principali

### CloudKiller 2.0
- **Multithreading avanzato**: Esegui scansioni rapide con supporto per thread multipli
- **Integrazione Discord**: Ricevi notifiche in tempo reale quando vengono trovati nuovi sottodomini
- **Validazione DNS robusta**: Verifica sottodomini con diversi metodi (DNS, HTTP, ping)
- **Sistema di configurazione**: Personalizza facilmente tutte le opzioni tramite file di configurazione
- **Rilevamento di IP reali**: Bypassa protezioni cloud per trovare gli indirizzi IP reali
- **Reporting dettagliato**: Output in diversi formati (CSV, JSON)
- **Interfaccia a colori**: Visualizzazione chiara dei risultati con supporto cross-platform
- **Ripresa delle scansioni**: Possibilità di riprendere scansioni interrotte

### CloudKiller Pro 3.0 (Funzionalità aggiuntive)
- **🔍 Risoluzione DNS passiva**: Utilizza servizi come crt.sh, SecurityTrails, dns.bufferover.run, Anubis e altri
- **🧠 Wordlist dinamiche**: Generazione intelligente di sottodomini basati su modelli
- **🛡️ Bypass avanzato di WAF/CDN**: Tecniche sofisticate per aggirare protezioni cloud
- **🧩 Rilevamento IP Origin**: Verifica se un sottodominio espone il vero IP di origine
- **🧠 Fingerprinting tecnologie**: Identifica CMS, framework, server web e altre tecnologie
- **🔍 Controllo vulnerabilità**: Verifica automatica di vulnerabilità comuni
- **📂 Enumerazione directory**: Ricerca automatica di percorsi sensibili
- **🤖 Integrazione Telegram**: Supporto per notifiche via Telegram oltre a Discord
- **🔐 Analisi certificati SSL**: Estrazione di informazioni dettagliate dai certificati SSL
- **🔎 Verifica takeover**: Controllo della possibilità di takeover di sottodomini
- **⚡ Anti rate-limit**: Sistemi avanzati per evitare blocchi durante le scansioni
- **🗺️ Scanning ricorsivo**: Scansione dei sottodomini dei sottodomini trovati
- **🔄 Resume avanzato**: Sistema migliorato per riprendere scansioni interrotte

## 📋 Prerequisiti

- Python 3.7 o superiore
- Connessione internet
- Permessi per eseguire ping e richieste HTTP

## 🔧 Installazione

1. Clona il repository:
```bash
git clone https://github.com/next-code-community/CloudKillerPro
cd CloudKillerPro
```

2. Installa le dipendenze:
```bash
pip install -r requisiti.txt
```

3. Assicurati di avere un file di wordlist (`subl.txt`) nella stessa directory

## 🏃‍♂️ Utilizzo di base

### Modalità interattiva
```bash
python cloudkiller.py
```

### Con parametri
```bash
python cloudkiller.py -d example.com -w wordlist.txt --webhook https://discord.com/api/webhooks/your-webhook-url
```

### Opzioni avanzate
```bash
# Modalità passiva (solo fonti pubbliche)
python cloudkiller.py -d example.com --passive

# Scansione con proxy
python cloudkiller.py -d example.com --proxy 127.0.0.1:8080

# Senza analisi aggiuntiva (più veloce)
python cloudkiller.py -d example.com --no-analysis
```

### Tutte le opzioni disponibili
```
-d, --domain       Dominio target (es. example.com)
-w, --wordlist     Percorso alla wordlist dei sottodomini
-o, --output       Nome del file di output
-t, --threads      Numero di thread da utilizzare
--webhook          URL webhook Discord per le notifiche
--config           Percorso al file di configurazione personalizzato
--passive          Usa solo riconoscimento passivo (no scansioni attive)
--no-analysis      Disabilita analisi aggiuntive
--proxy            Usa proxy (formato: host:port)
--version          Mostra la versione del programma
```

## ⚙️ Configurazione

CloudKiller Pro utilizza un file di configurazione (`cloudkiller.conf`) per le impostazioni avanzate. Puoi modificare questo file per personalizzare il comportamento dello strumento.

### Sezioni di configurazione
- **General**: Impostazioni generali come thread, timeout, ecc.
- **HTTP**: Configurazione delle richieste HTTP
- **Output**: Opzioni per il reporting e logging
- **Analysis**: Controlli per funzionalità di analisi aggiuntive
- **Passive**: Fonti per la scoperta passiva di sottodomini
- **API_Keys**: Chiavi API per servizi di terze parti
- **Discord**: Configurazione notifiche Discord
- **Telegram**: Configurazione notifiche Telegram
- **Advanced**: Impostazioni avanzate come profondità ricorsiva

## 📊 Esempio di output

Un file di report generato (`Report_example.com.csv`) avrà un formato simile:

```
subdomain,ip_address,status_code,protocol,response_time_ms,server,technologies,waf
mail.example.com,192.168.1.10,200,http,342.5,Apache,PHP|Postfix,Cloudflare
api.example.com,192.168.1.15,403,https,120.8,nginx,Node.js|Express,AWS WAF
dev.example.com,192.168.1.20,200,http,250.3,IIS,ASP.NET|SQL Server,
```

Inoltre, CloudKiller Pro genera:
- Report JSON dettagliati per ogni dominio
- File di riepilogo con statistiche e metriche
- Dati dettagliati su tecnologie e WAF rilevati

## 🔍 Come funziona

CloudKiller Pro utilizza un approccio multi-fase per scoprire e analizzare sottodomini:

1. **Enumerazione multi-fonte**: Combina wordlist con dati da fonti passive come crt.sh
2. **Generazione intelligente**: Crea permutazioni e varianti di sottodomini conosciuti
3. **Validazione multi-metodo**: Verifica attraverso DNS, HTTP/HTTPS e ping
4. **Bypass protezioni**: Utilizza tecniche avanzate per aggirare WAF e CDN
5. **Analisi approfondita**: Fingerprinting di tecnologie, controllo vulnerabilità, ecc.
6. **Scansione ricorsiva**: Cerca sottodomini dei sottodomini già trovati
7. **Reporting esteso**: Genera report dettagliati e invia notifiche in tempo reale

## 🔒 Uso etico e disclaimer

CloudKiller Pro è progettato per essere utilizzato in modo etico e legale, come parte di valutazioni di sicurezza autorizzate. Non utilizzare questo strumento su sistemi o domini per i quali non hai esplicita autorizzazione.

**Disclaimer**: L'autore non si assume alcuna responsabilità per l'uso improprio di questo strumento o per eventuali danni causati dal suo utilizzo. L'utente è l'unico responsabile dell'uso corretto e legale di CloudKiller Pro.

## 🤝 Contribuire

I contributi sono benvenuti! Se vuoi migliorare CloudKiller Pro, puoi:

1. Forkare il repository
2. Creare un branch per la tua feature (`git checkout -b feature/nuova-feature`)
3. Committare le tue modifiche (`git commit -m 'Aggiunta nuova feature'`)
4. Pushare sul branch (`git push origin feature/nuova-feature`)
5. Aprire una Pull Request

## 📜 Licenza

Questo progetto è distribuito sotto licenza MIT. Vedi il file `LICENSE` per ulteriori dettagli.

## 🙏 Riconoscimenti

- NC (github.com/next-code-community) - Creatore originale

## 📞 Contatti

Per domande, suggerimenti o problemi, puoi:
- Aprire un issue su GitHub
- Contattare l'autore tramite GitHub
