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
docker build --no-cache -f "./compose/local/django/Dockerfile" -t  "rao-app:<tag>" 
```

Sostituire a `<tag>` un'etichetta per identificativa dell'immagine Docker (esempio `latest`).

L'immagine copia il contenuto della cartella `./rao` e lo script di avvio `./compose/local/django/start` nel container.

### Utilizzo dell'immagine Docker

L'immagine espone la porta `8000/TCP` e il volume `/data`.

Per la configurazione sono utilizzate le seguenti variabili di ambiente:

| Variablie          | Descrizione                                                  |
| ------------------ | ------------------------------------------------------------ |
| `SIGN_URL`         | Url delle API del server di firma (esempio: http://signserver.sielte.it/v2/). |
| `BASE_URL`         | Url di base su cui risponderà il servizio RAO (esempio: https://test-rao.sielte.it/). |
| `SECRET_KEY`       | Una stringa alfanumerica utilizzare per la codifica interna. Se non impostata verrà utilizzato un valore generato casualmente. |
| `DATABASE_NAME`    | Percorso completo del file del database sqLite che verrà usato dall'applicazione (predefinito `./data/raodb.sqlite3`) |
| `MAIL_LOG_LEVEL`   | Livello di verbosità dei log che verranno inviati per email (predefinto `ERROR`) |
| `PORTAL_LOG_LEVEL` | Livello di verbosità dei log del portale (predefinito `DEBUG`) |
| `AGENCY_LOG_LEVEL` | Livello di verbosità dei log dell'agency (predefinito `DEBUG`) |
| `SECRET_KEY_ENC`   | Una stringa alfanumerica utilizzare per la codifica delle chiavi. Se non impostata verrà utilizzato un valore generato casualmente.ì |


Nel caso di utilizzo dell'immagine con *Docker* si consiglia di creare un *volume* con il comando:

```bash
docker volume create "<nome_volume>" &> /dev/null || true
```

Esecuzione dell'immagine (sostituire opportunamente i valori dei dati tra parentesi angolari `<...>`):

```bash
docker run -d \
       --name "<nome_container>" \
       -e SECRET_KEY="<chiave>" \
       -e DATABASE_NAME="/data/<nomedb>.sqlite3" \
       -e MAIL_LOG_LEVEL="ERROR" \
       -e AGENCY_LOG_LEVEL="INFO" \
       --mount type=volume,source="<nome_volume",target="/data" \
       -p "<porta>:8000" \
       "rao-app:lastest"  "/start"
```

## Configurazione (inizializzazione dei dati)

Al primo avvio del progetto, si verrà re-indirizzati su:

``https://..../setup``


Attraverso questo link verrà visualizzato un form con i seguenti campi che dovrà compilare l'UNICO utente AMMINISTRATORE del sistema:
 * codice fiscale dell'amministratore (campo username)
 * nome dell'amministratore
 * cognome dell'amministratore
 * email dell'amministratore
 * conferma email
 * nome del comune
 * Codice identificativo IPA
 * Campo "Da"
 * username email SMTP
 * password 
 * Host Posta in Uscita (SMTP)
 * Porta in Uscita (SMTP)
 * Crittografia (Nessuna/SSL/TLS)
 
Queste informazioni serviranno ad inizializzare un utente admin, a impostare il nome relativo all'agenzia\comune che utilizzerà il servizio
e a configurare il server email che provvederà ad inviare le varie email precompilate dall'applicativo.

Una volta compilato il form, verrà inviata un'email di conferma all'indirizzo email dell'amministratore contenente il link di verifica; al click
su di esso verrà richiesto di inserire la propria password.
Teminata questa prima fase di setup viene avviata in automatico una procedura per il popolamento di alcuni dati, quali:
 * comuni
 * province
 * nazioni
 * ecc..

(Questa operazione potrebbe richiedere tempo)

Un ultimo passaggio necessario per l'attivazione del proprio account comporta l'insererimento dei seguenti dati:
 * pin di Firma temporaneo
 * nuovo pin di Firma formato da 6 caratteri numerici
 * conferma pin
 * certificato 

L'utente amministratore sarà quindi attivo: giungerà sulla pagina di login e potrà effettuare l'accesso 
con le credenziali inserite durante il processo di attivazione.

## Utilizzo dell'applicativo

### Ruoli
L'Operatore ADMIN potrà:
* visualizzare l'elenco delle richieste di identificazione effettuate dagli operatori
* visualizzare l'elnco degli operatori
* aggiungere un nuovo operatore
* visualizzare la dashboard delle richieste di identificazione nel tempo

L'Operatore R.A.O potrà:
* visualizzare l'elenco delle richieste di identità da lui effettuate
* inserire una nuova richiesta di identificazione


### Creazione nuovo Operatore
L'utente ADMIN cliccando su "Aggiungi operatore" e compilando l'apposito form potrà inserire un nuovo Operatore R.A.O (ultimato il form,
sarà necessario inserire il proprio PIN di Firma per concludere l'operazione); verrà generato automaticamente un pdf contenente il pin temporaneo
che l'operatore dovrà inserire in fase di attivazione del proprio account.

L'operatore inserito riceverà un link di verifica presso l'indirizzo di posta indicato dall'utente ADMIN durante la compilazione del form.
Al click sul link il nuovo Operatore dovrà scegliere una password valida e modificare il PIN di Firma temporaneo (fornito dall'ADMIN)
prima di poter effettuare l'accesso e iniziare ad utilizzare l'applicativo per le Identificazioni SPID.

### Creazione nuova richiesta di identificazione
L'Operatore R.A.O cliccando su "Aggiungi richiesta" e compilando l'apposito form potrà inserire una nuova richiesta di identificazione.
Ultimato il form, sarà necessario inserire il proprio PIN di Firma per concludere l'operazione.
Una volta terminato, l'operatore R.A.O. dovrà stampare la prima metà della password del token sigillato dell'utente e consegnarla di persona. 
L'utente che ha richiesto l'identificazione riceverà il token sigillato e la seconda metà della password all'indirizzo email fornito per l'identificazione.
