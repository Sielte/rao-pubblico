# Changelog
Tutte le modifiche al progetto, nuove funzionalità e informazioni sono documentate in questo file.

## [1.0.3] - 03/12/2020

### Nuove funzionalità

- Adeguamento degli indirizzi email ad un sottoinsieme più ampio delle specifiche previste dallo standard relativo;
- Rafforzamento della sanificazione dei dati inseriti;
- Modale per la correzione di CF o IPA nel caso si riscontrino errori durante la fase di impostazione del PIN;
- Classe version_filter.py per la gestione dei log.

### Modifiche

- Modifica dei testi;
- Rimozione Identity Request da tabella in caso di invio email non riuscito;
- Comune di nascita con verifica su data di istituzione;
- Rimozione controllo sulla data  di scadenza;
- Rimozione suggerimento password sulla pagina di login.

### Fix

- Messaggio di conferma/errore nella schermata di recupero password;
- Errata visualizzazione Dashboard con tabella e grafico privi di valori su Docker;

## [1.0.2] - 26/10/2020

### Nuove funzionalità

- Cartella compose;

### Modifiche

- Aggiornamento testo schermata summary_identity;
- Scelta manuale provincia/comune di nascita;
- Aggiornamento upload Comuni;
- Aggiornamento link per scelta IdP;
- Rimozione richieste (polling ok http) dai log; 
- Livello dei log.

### Fix

- Data di rilascio documento;
- Stato estero sul codice fiscale;
- Formato data di nascita.

 
## [1.0.1] - 08/10/2020


### Modifiche

- Miglioramento template mail e pdf;
- Modalità di caricamento del certificato.
 

### Fix

- Logging;
- Variabili di sessione;
- Verifica crl.

## [1.0.0] - 16/09/2020

- First commit.
 
