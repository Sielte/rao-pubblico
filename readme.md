# R.A.O. Pubblico

## Introduzione

Il seguente progetto mette a disposizione dei R.A.O. pubblici una piattaforma contenente le funzionalità basilari per il processo di identificazione SPID.

Per un corretto funzionamento del sistema sarà necessario configurare il Server di Firma **rao-pubblico-signer**, che avrà il compito di autorizzare tramite pin 
le operazioni del Security Officer (Amministratore del R.A.O.) e degli operatori del R.A.O. È possibile accedere al repository di rao-pubblico-signer tramite
il link di cui sotto:

``https://github.com/Sielte/rao-pubblico-signer.git``


## Installazione con Docker

È possibile installare ed eseguire l'applicazione RAO in un container *Docker*, allo scopo è stato preparato un `Dockerfile` basato sull'immagine python:3.6.

Il `Dockerfile` genera un'immagine compatibile con gli orchestratori OpenShift e Kubernetes.

### Build dell'immagine Docker

Processo di building dell'immagine Docker:

Dalla directory principale del progetto lanciare il comando:

```bash
docker build --no-cache -f "./compose/local/django/Dockerfile" -t  "rao-app:<tag>" .
```

Sostituire a `<tag>` un'etichetta per identificativa dell'immagine Docker (esempio `latest`).

L'immagine copia il contenuto della directory `./rao`, lo script di avvio `./compose/local/django/start` e quello di entrypoint `./compose/production/django/entrypoint` nel container.

### Utilizzo dell'immagine Docker

L'immagine espone la porta `8000/TCP` e il volume `/data`.

Per la configurazione sono utilizzate le seguenti variabili di ambiente:

| Variablie          | Descrizione                                                  |
| ------------------ | ------------------------------------------------------------ |
| `SIGN_URL`         | URL delle API del server di firma (esempio: http://signserver.sielte.it/v2/). |
| `BASE_URL`         | URL di base su cui risponderà il servizio RAO (esempio: https://test-rao.sielte.it/). |
| `SECRET_KEY`       | Una stringa alfanumerica da utilizzare per le funzionalità di sicurezza interne di Django. Se non impostata verrà utilizzato un valore generato casualmente. |
| `DATABASE_NAME`    | Percorso completo del file del database SQLite che verrà usato dall'applicazione (predefinito `./data/raodb.sqlite3`) |
| `MAIL_LOG_LEVEL`   | Livello di verbosità dei log che verranno inviati per e-mail (predefinito `ERROR`) |
| `PORTAL_LOG_LEVEL` | Livello di verbosità dei log del portale (predefinito `DEBUG`) |
| `AGENCY_LOG_LEVEL` | Livello di verbosità dei log dell'agency (predefinito `DEBUG`) |
| `SECRET_KEY_ENC`   | Una stringa alfanumerica da utilizzare per la crittografia delle password degli operatori. Se non impostata verrà utilizzato un valore generato casualmente. |
| `RAO_NAME`         | Nome/Identificativo del R.A.O. (es. Catania) |


Nel caso di utilizzo dell'immagine con *Docker* si consiglia di creare un *volume* con il comando:

```bash
docker volume create "<nome_volume>" &> /dev/null || true
```

Esecuzione dell'immagine (sostituire opportunamente i valori dei dati tra parentesi angolari `<...>`):

```bash
docker run -d \
       --name "<nome_container>" \
       -e SIGN_URL="<signURL>" \
       -e BASE_URL="<baseURL>"
       -e SECRET_KEY="<chiaveSegreta1>" \
       -e DATABASE_NAME="/data/<nomedb>.sqlite3" \
       -e MAIL_LOG_LEVEL="ERROR" \
       -e PORTAL_LOG_LEVEL="INFO" \
       -e AGENCY_LOG_LEVEL="INFO" \
       -e SECRET_KEY_ENC="<chiaveSegreta2>" \
       -e RAO_NAME="<nomeRAO>" \
       --mount type=volume,source="<nome_volume>",target="/data" \
       -p "<porta>:8000" \
       "rao-app:latest"  "/start"
```

## Configurazione (inizializzazione dei dati)

Al primo avvio del progetto, si verrà re-indirizzati su:

``https://..../agency/setup``


Attraverso questo link verrà visualizzato un form con i seguenti campi che dovrà compilare l'UNICO utente AMMINISTRATORE del sistema:
 * codice fiscale dell'Amministratore (campo username)
 * nome dell'Amministratore
 * cognome dell'Amministratore
 * e-mail dell'Amministratore
 * conferma e-mail
 * nome del comune
 * codice identificativo IPA
 * campo "Da"
 * username posta in uscita (SMTP)
 * password posta in uscita (SMTP)
 * host posta in uscita (SMTP)
 * porta posta in uscita (SMTP)
 * crittografia posta in uscita (Nessuna/SSL/TLS)
 
Queste informazioni serviranno ad inizializzare un utente admin, a impostare il nome relativo all'agenzia/comune che utilizzerà il servizio
e a configurare il server e-mail che provvederà ad inviare le varie e-mail precompilate dall'applicativo.

Una volta compilato il form, verrà inviata un'e-mail di conferma all'indirizzo e-mail dell'amministratore contenente il link di verifica; al click
su di esso verrà richiesto di inserire la propria password.
Teminata questa prima fase di setup viene avviata in automatico una procedura per il popolamento di alcuni dati, quali:
 * comuni
 * province
 * nazioni
 * ecc..

(Questa operazione potrebbe richiedere tempo)

Un ultimo passaggio necessario per l'attivazione del proprio account comporta l'inserimento dei seguenti dati:
 * PIN di Firma temporaneo
 * nuovo PIN di Firma formato da 6 caratteri numerici
 * conferma PIN
 * certificato 
 * chiave privata

L'utente Amministratore sarà quindi attivo: potrà raggiungere la pagina di login ed effettuare l'accesso 
con le credenziali inserite durante il processo di attivazione.

## Utilizzo dell'applicativo

### Ruoli
L'Operatore ADMIN potrà:
* visualizzare l'elenco delle richieste di identificazione effettuate dagli operatori
* visualizzare l'elnco degli operatori
* aggiungere un nuovo operatore
* visualizzare la dashboard delle richieste di identificazione effettuate nel tempo
* aggiornare certificato/chiave pubblica e riconfigurare il server di Posta in Uscita

L'Operatore R.A.O potrà:
* visualizzare l'elenco delle richieste di identità da lui effettuate
* inserire una nuova richiesta di identificazione


### Creazione nuovo Operatore
L'utente ADMIN cliccando su "Aggiungi operatore" e compilando l'apposito form potrà inserire un nuovo Operatore R.A.O. (ultimato il form,
sarà necessario inserire il proprio PIN di Firma per concludere l'operazione); verrà generato automaticamente un file PDF contenente il PIN temporaneo
che l'operatore dovrà inserire in fase di attivazione del proprio account.

L'operatore inserito riceverà un link di verifica presso l'indirizzo di posta indicato dall'utente Amministratore durante la compilazione del form.
Al click sul link il nuovo Operatore dovrà scegliere una password valida e modificare il PIN di Firma temporaneo (fornito dall'Amministratore)
prima di poter effettuare l'accesso ed iniziare ad utilizzare l'applicativo per le Identificazioni SPID.

### Creazione nuova richiesta di identificazione
L'Operatore R.A.O cliccando su "Aggiungi richiesta" e compilando l'apposito form potrà inserire una nuova richiesta di identificazione.
Ultimato il form, sarà necessario inserire il proprio PIN di Firma per concludere l'operazione.
Una volta terminato, l'operatore R.A.O. dovrà stampare la prima metà della password del token dell'utente su cui è stato apposto il sigillo e consegnarla di persona.
L'utente che ha richiesto l'identificazione riceverà il token su cui è stato apposto il sigillo e la seconda metà della password all'indirizzo e-mail fornito per l'identificazione.
