# CloudKiller 2.0

![Banner](https://img.shields.io/badge/CloudKiller-2.0-brightgreen)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Bypass Cloud Protection - Advanced Subdomain Discovery Tool

CloudKiller è uno strumento avanzato per la scoperta di sottodomini che bypassa le protezioni cloud comuni. Progettato per penetration tester, security researcher e professionisti della sicurezza, CloudKiller consente di scoprire asset nascosti o dimenticati che potrebbero rappresentare una superficie di attacco per la tua organizzazione.

![CloudKiller Screenshot](https://placeholder-image.com/cloudkiller-screenshot.png)

## 🚀 Caratteristiche principali

- **Multithreading avanzato**: Esegui scansioni rapide con supporto per thread multipli
- **Integrazione Discord**: Ricevi notifiche in tempo reale quando vengono trovati nuovi sottodomini
- **Validazione DNS robusta**: Verifica sottodomini con diversi metodi (DNS, HTTP, ping)
- **Sistema di configurazione**: Personalizza facilmente tutte le opzioni tramite file di configurazione
- **Rilevamento di IP reali**: Bypassa protezioni cloud per trovare gli indirizzi IP reali
- **Reporting dettagliato**: Output in diversi formati (CSV, JSON)
- **Interfaccia a colori**: Visualizzazione chiara dei risultati con supporto cross-platform
- **Ripresa delle scansioni**: Possibilità di riprendere scansioni interrotte

## 📋 Prerequisiti

- Python 3.7 o superiore
- Connessione internet
- Permessi per eseguire ping e richieste HTTP

## 🔧 Installazione

1. Clona il repository:
```bash
git clone https://github.com/next-code-community/CloudKiller2.0
cd CloudKiller2.0
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

### Opzioni disponibili
```
-d, --domain       Dominio target (es. example.com)
-w, --wordlist     Percorso alla wordlist dei sottodomini
-o, --output       Nome del file di output
-t, --threads      Numero di thread da utilizzare
--webhook          URL webhook Discord per le notifiche
--config           Percorso al file di configurazione personalizzato
```

## ⚙️ Configurazione

CloudKiller utilizza un file di configurazione (`cloudkiller.conf`) per le impostazioni avanzate. Puoi modificare questo file per personalizzare il comportamento dello strumento.

### Esempio di configurazione
```ini
[General]
threads = 50
timeout = 5
user_agent = Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
verify_ssl = False

[HTTP]
methods = GET
follow_redirects = True
max_redirects = 3

[Output]
verbose = True
show_progress = True
output_format = csv

[Discord]
enabled = True
webhook_url = 
notification_threshold = 1
embed_color = 5814783
```

## 📊 Esempio di output

Un file di report generato (`Report_example.com.csv`) avrà un formato simile:

```
subdomain,ip_address,status_code,protocol,response_time_ms
mail.example.com,192.168.1.10,200,http,342.5
api.example.com,192.168.1.15,403,https,120.8
dev.example.com,192.168.1.20,200,http,250.3
```

## 🔍 Come funziona

CloudKiller utilizza un approccio multi-fase per scoprire sottodomini:

1. **Enumerazione**: Genera possibili sottodomini combinando il dominio target con una wordlist
2. **Validazione DNS**: Verifica se i sottodomini si risolvono correttamente
3. **Controllo HTTP/HTTPS**: Tenta di connettersi ai sottodomini tramite HTTP e HTTPS
4. **Rilevamento IP**: Utilizza tecniche di ping e socket per determinare gli indirizzi IP reali
5. **Elaborazione e rapporto**: Salva i risultati e invia notifiche Discord (se configurate)

## 🔒 Uso etico e disclaimer

CloudKiller è progettato per essere utilizzato in modo etico e legale, come parte di valutazioni di sicurezza autorizzate. Non utilizzare questo strumento su sistemi o domini per i quali non hai esplicita autorizzazione.

**Disclaimer**: L'autore non si assume alcuna responsabilità per l'uso improprio di questo strumento o per eventuali danni causati dal suo utilizzo. L'utente è l'unico responsabile dell'uso corretto e legale di CloudKiller.

## 🤝 Contribuire

I contributi sono benvenuti! Se vuoi migliorare CloudKiller, puoi:

1. Forkare il repository
2. Creare un branch per la tua feature (`git checkout -b feature/nuova-feature`)
3. Committare le tue modifiche (`git commit -m 'Aggiunta nuova feature'`)
4. Pushare sul branch (`git push origin feature/nuova-feature`)
5. Aprire una Pull Request

## 📜 Licenza

Questo progetto è distribuito sotto licenza MIT. Vedi il file `LICENSE` per ulteriori dettagli.

## 🙏 Riconoscimenti

- FD (github.com/next-code-community) - Creatore originale

## 📞 Contatti

Per domande, suggerimenti o problemi, puoi:
- Aprire un issue su GitHub
- Contattare l'autore tramite GitHub
