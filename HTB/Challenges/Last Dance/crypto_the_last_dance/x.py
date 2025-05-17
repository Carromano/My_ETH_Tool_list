# reverse_script_manual_input.py
# Questo script è progettato per decifrare la flag quando lo stesso keystream ChaCha20
# è stato riutilizzato per cifrare un messaggio conosciuto e una flag segreta.
# Modificato per accettare input esadecimali direttamente nello script.

# Il messaggio in chiaro conosciuto, esattamente come nello script originale.
KNOWN_MESSAGE = (
    b"Our counter agencies have intercepted your messages and a lot "
    b"of your agent's identities have been exposed. In a matter of "
    b"days all of them will be captured"
)

def hex_to_bytes(hex_string):
    """Converte una stringa esadecimale in bytes."""
    if not hex_string or hex_string.startswith("INCOLLA QUI"):
        raise ValueError(f"La stringa esadecimale '{hex_string}' non è valida o non è stata fornita.")
    return bytes.fromhex(hex_string)

def xor_bytes(bytes1, bytes2):
    """
    Esegue l'operazione XOR byte per byte tra due sequenze di byte.
    La lunghezza del risultato è la minima tra le lunghezze dei due input.
    """
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))

def main():
    """
    Funzione principale per prendere gli input esadecimali, recuperare il keystream
    e decifrare la flag.
    """
    # --- INCOLLA QUI I TUOI VALORI ESADECIMALI ---
    # Assicurati che queste stringhe contengano solo caratteri esadecimali validi.
    # NON includere "0x" all'inizio delle stringhe esadecimali.

    # L'IV (nonce) in formato esadecimale.
    # Anche se l'IV è cruciale per la generazione del keystream originale,
    # non è direttamente usato nei calcoli XOR di questo script di attacco.
    iv_hex_input = "c4a66edfe80227b4fa24d431"

    # Il messaggio cifrato (corrispondente a KNOWN_MESSAGE) in formato esadecimale.
    # QUESTO È NECESSARIO per calcolare il keystream.
    encrypted_message_hex_input = "7aa34395a258f5893e3db1822139b8c1f04cfab9d757b9b9cca57e1df33d093f07c7f06e06bb6293676f9060a838ea138b6bc9f20b08afeb73120506e2ce7b9b9dcd9e4a421584cfaba2481132dfbdf4216e98e3facec9ba199ca3a97641e9ca9782868d0222a1d7c0d3119b867edaf2e72e2a6f7d344df39a14edc39cb6f960944ddac2aaef324827c36cba67dcb76b22119b43881a3f1262752990"

    # La flag cifrata in formato esadecimale.
    encrypted_flag_hex_input = "7d8273ceb459e4d4386df4e32e1aecc1aa7aaafda50cb982f6c62623cf6b29693d86b15457aa76ac7e2eef6cf814ae3a8d39c7"
    # --- FINE DELLA SEZIONE INPUT ---

    try:
        # Converte le stringhe esadecimali in byte.
        # iv_bytes = hex_to_bytes(iv_hex_input) # Non usato nell'attacco XOR diretto, ma convertito per completezza.
        encrypted_message_bytes = hex_to_bytes(encrypted_message_hex_input)
        encrypted_flag_bytes = hex_to_bytes(encrypted_flag_hex_input)
    except ValueError as e:
        print(f"Errore nella conversione da esadecimale a byte: {e}")
        print("Controlla di aver incollato correttamente i valori esadecimali nelle variabili.")
        print("Assicurati che non ci siano caratteri non validi e che le stringhe non siano vuote.")
        return
    except Exception as e:
        print(f"Si è verificato un errore imprevisto durante la preparazione dei dati: {e}")
        return

    # Stampa di debug (opzionale) per verificare le lunghezze.
    # print(f"Lunghezza del messaggio conosciuto: {len(KNOWN_MESSAGE)}")
    # print(f"Lunghezza del messaggio cifrato fornito: {len(encrypted_message_bytes)}")
    # print(f"Lunghezza della flag cifrata fornita: {len(encrypted_flag_bytes)}")

    # Verifica che la lunghezza del messaggio conosciuto corrisponda a quella del messaggio cifrato.
    # Per ChaCha20 (e cifrari a flusso in generale), la lunghezza del testo cifrato
    # è uguale a quella del testo in chiaro.
    if len(KNOWN_MESSAGE) != len(encrypted_message_bytes):
        print("Attenzione: La lunghezza del KNOWN_MESSAGE non corrisponde alla lunghezza")
        print("del messaggio cifrato fornito. Questo potrebbe indicare un problema.")
        # Potrebbe essere comunque possibile recuperare una parte del keystream.

    # 1. Recupera il keystream: Keystream = Plaintext_Conosciuto XOR Ciphertext_Conosciuto
    # La lunghezza del keystream recuperato sarà min(len(KNOWN_MESSAGE), len(encrypted_message_bytes)).
    keystream = xor_bytes(KNOWN_MESSAGE, encrypted_message_bytes)
    # print(f"Lunghezza del keystream recuperato: {len(keystream)}")

    if not keystream:
        print("Errore: il keystream calcolato è vuoto. Controlla gli input.")
        return

    # 2. Decifra la flag: Plaintext_Flag = Ciphertext_Flag XOR Keystream
    # L'operazione XOR sarà limitata dalla lunghezza più corta tra encrypted_flag_bytes e keystream.
    # Se la flag è più lunga del messaggio conosciuto (e quindi del keystream recuperato),
    # solo una parte della flag verrà decifrata.
    decrypted_flag_bytes = xor_bytes(encrypted_flag_bytes, keystream)

    print("\nFLAG DECIFRATA:")
    try:
        # Tenta di decodificare la flag come UTF-8, formato comune per le flag nelle CTF.
        print(decrypted_flag_bytes.decode('utf-8'))
    except UnicodeDecodeError:
        # Se la decodifica UTF-8 fallisce, stampa i byte grezzi e la loro rappresentazione esadecimale.
        print("Impossibile decodificare la flag come UTF-8.")
        print(f"Byte grezzi: {decrypted_flag_bytes}")
        print(f"Rappresentazione esadecimale: {decrypted_flag_bytes.hex()}")

if __name__ == "__main__":
    main()
