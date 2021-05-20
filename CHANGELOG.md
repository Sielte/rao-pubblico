# Changelog
Tutte le modifiche al progetto, nuove funzionalità e informazioni sono documentate in questo file.

## [1.0.11] - 20/05/2021

### Modifiche

- Aggiornamento versione di django (2.2.23).


## [1.0.10] - 12/02/2021

### Fix

- Risolto problema relativo al link del cambio password


## [1.0.9] - 08/02/2021

### Fix

- Correzioni relative alla versione 1.0.8.

### Modifiche

- Inserimento migrations 0002.


## [1.0.8] - 03/02/2021

### Fix

- Rimosso il messaggio "ritrasmetti" al termine del caricamento dei dati che appariva su alcuni browser;
- Miglioramento grafico alla barra di caricamento che appare durante il processo di setup.
- Miglioramento messaggi di errore all'interno della pagina di creazione operatore:
    - I messaggi mostrati a schermo indicano più precisamente il problema;
    - La finestra di inserimento PIN si chiude in caso di errore.
     
### Modifiche

- I campi del modulo per la nuova richiesta di identificazione presentano tutti un'etichetta per evidenziare il tipo di dato da inserire;
- Prefisso internazione pre-popolato con '+39';
- Nazione di domicilio pre-popolato con 'Italia';


## [1.0.7] - 21/01/2021

### Fix

- Il controllo sul numero di documento verifica anche i casi di CIE 2.0.


## [1.0.6] - 21/01/2021

### Fix

- Modifica alla variabile DATA_FILES_PATH nel file settings.py


## [1.0.5] - 20/01/2021

### Modifiche

- Nel caso in cui il codice fiscale non corrisponda ai dati anagrafici inseriti:
	- La schermata di riepilogo presenta un testo informativo in rosso in cui viene avvisato l'operatore della non conformità dei dati;
		- I dati che causano l'errore sono evidenziati in rosso;
	- Qualora l'operatore voglia comunque proseguire, dovrà spuntare la casella in fondo alla pagina;
	- Il pulsante di identificazione risulta disabilitato finchè la casella rimane non spuntata.

### Fix

- Inserimento delle nazioni soppresse visualizzate esclusivamente tra le nazioni di nascita;
- Nuovi controlli sulla validità del codice fiscale del cittadino;


## [1.0.4] - 11/01/2021

### Fix

- Refactoring di alcune funzioni;
- Miglioramento dei controlli sul campo idCardIssuer.

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
 
