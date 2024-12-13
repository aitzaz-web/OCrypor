open Encryptor.Rsa
open Encryptor.Ecc
open Encryptor.Util
open Encryptor.Sha3
open Encryptor.Aes128
open Encryptor.Blowfish

(**encrypt_file_blowfish encrypts the contents of the file at filename using the
   user's key. *)
let encrypt_file_blowfish filename key =
  try
    let content = BatFile.with_file_in filename BatIO.read_all in
    let rec split_into_chunks s chunk_size =
      if String.length s <= chunk_size then [ s ]
      else
        let chunk = String.sub s 0 chunk_size in
        let rest = String.sub s chunk_size (String.length s - chunk_size) in
        chunk :: split_into_chunks rest chunk_size
    in
    let chunk_size = 8 in
    let message_chunks = split_into_chunks content chunk_size in
    let encrypted_chunks =
      List.map (fun chunk -> encrypt chunk key) message_chunks
    in
    let encrypted_message = String.concat "" encrypted_chunks in
    let encrypted_filename = filename ^ ".enc.blowfish" in
    BatFile.with_file_out encrypted_filename (fun out ->
        BatIO.nwrite out encrypted_message);
    print_endline ("File encrypted successfully. Saved as " ^ encrypted_filename)
  with _ -> failwith "Error occurred during file level encryption."

(**decrypt_file_blowfish decrypts the contents of the encrypted file at filename
   using the user's key (same key that was used for encryption). *)
let decrypt_file_blowfish filename key =
  try
    let content = BatFile.with_file_in filename BatIO.read_all in
    let rec split_encrypted s chunk_sizes acc =
      match chunk_sizes with
      | [] -> List.rev acc
      | size :: rest ->
          let chunk = String.sub s 0 size in
          let remaining = String.sub s size (String.length s - size) in
          split_encrypted remaining rest (chunk :: acc)
    in
    let chunk_size = 96 in
    let rec split_into_chunks s chunk_size =
      if String.length s <= chunk_size then [ String.length s ]
      else
        chunk_size
        :: split_into_chunks
             (String.sub s chunk_size (String.length s - chunk_size))
             chunk_size
    in
    let chunk_sizes = split_into_chunks content chunk_size in
    let encrypted_chunks_split = split_encrypted content chunk_sizes [] in
    let decrypted_chunks =
      List.map (fun chunk -> decrypt chunk key) encrypted_chunks_split
    in
    let decrypted_message = String.concat "" decrypted_chunks in
    let decrypted_filename = filename ^ ".dec.blowfish" in
    BatFile.with_file_out decrypted_filename (fun out ->
        BatIO.nwrite out decrypted_message);
    print_endline ("File decrypted successfully. Saved as " ^ decrypted_filename)
  with _ -> failwith "Error occurred during file level decryption."

(* Function to read a file and return its contents *)
let read_file filename =
  try
    let in_channel = open_in filename in
    let file_content =
      really_input_string in_channel (in_channel_length in_channel)
    in
    close_in in_channel;
    Some file_content
  with Sys_error err ->
    Printf.printf "Error: %s\n" err;
    None

(* Function to write contents to a file *)
let write_to_file filename content =
  let oc = open_out filename in
  Printf.fprintf oc "%s" content;
  close_out oc
(* Function to convert string to ASCII codes *)

let string_to_ascii message =
  List.map Char.code (List.of_seq (String.to_seq message))

(* Function to convert ASCII codes back to a string *)
let ascii_to_string ascii_codes =
  String.of_seq (List.to_seq (List.map Char.chr ascii_codes))

let ask_for_method () =
  Printf.printf
    "Choose an encryption method based on your data's safety requirements:\n\n";
  Printf.printf "1. RSA (Rivest–Shamir–Adleman)\n";
  Printf.printf
    "   - High Safety: Suitable for sensitive personal data, financial \
     records, or legal documents.\n";
  Printf.printf
    "   - Example: Encrypting financial reports or medical records.\n\n";
  Printf.printf "2. ECC (Elliptic Curve Cryptography)\n";
  Printf.printf
    "   - Medium Safety: Ideal for business files or private messages.\n";
  Printf.printf
    "   - Example: Securing emails, business contracts, or shared private \
     keys.\n\n";
  Printf.printf "3. SHA3/RC2 (Secure Hash Algorithm 3 / Rivest Cipher 2)\n";
  Printf.printf
    "   - Hashing/Integrity Check: Used for verifying file changes and \
     ensuring data integrity.\n";
  Printf.printf
    "   - Example: Ensuring a downloaded file hasn’t been altered.\n\n";
  Printf.printf "4. AES-128 (Advanced Encryption Standard)\n";
  Printf.printf
    "   - High Safety: Perfect for encrypting confidential documents or \
     high-value data.\n";
  Printf.printf
    "   - Example: Encrypting internal company files or trade secrets.\n\n";
  Printf.printf "5. Blowfish\n";
  Printf.printf
    "   - Low Safety: Suitable for non-critical or legacy files. Users can \
     create their own numeric keys for encryption.\n";
  Printf.printf
    "   - Example: Encrypting archived documents or small datasets in older \
     systems.\n\n";
  Printf.printf "Enter your choice (1-5): ";
  match read_line () with
  | "1" -> `RSA
  | "2" -> `ECC
  | "3" -> `SHA3
  | "4" -> `AES128
  | "5" -> `Blowfish
  | _ -> failwith "Invalid choice"

(* ECC Functions *)
let point_of_string s =
  if s = "Infinity" then ECC.Infinity
  else
    let trimmed = String.sub s 1 (String.length s - 2) in
    match String.split_on_char ',' trimmed with
    | [ x; y ] ->
        Point (int_of_string (String.trim x), int_of_string (String.trim y))
    | _ ->
        failwith "Invalid point format. Expected format: '(x, y)' or 'Infinity'"

let encrypt_message_ecc message base_point public_key a b p n =
  List.map (fun m -> ECC.encrypt m base_point public_key a b p n) message

let decrypt_message_ecc ciphertext private_key a p =
  String.concat ""
    (List.map
       (fun (c1, c2) ->
         let decrypted_char = ECC.decrypt (c1, c2) private_key a p in
         String.make 1 (Char.chr decrypted_char))
       ciphertext)

let ecc_workflow () =
  Printf.printf "Choose operation: 1 for Encrypt, 2 for Decrypt: ";
  let operation = read_line () in
  match operation with
  | "1" -> (
      (* Encryption Workflow *)
      Printf.printf "Enter the filename containing the message to encrypt: ";
      let filename = read_line () in
      match read_file filename with
      | Some content ->
          let message_ascii = string_to_ascii content in
          Printf.printf "Message as ASCII codes: %s\n"
            (String.concat ", " (List.map string_of_int message_ascii));
          let a, b, p, n = (2, 3, 97, 5) in
          let base_point = ECC.Point (3, 6) in
          let keys = ECC.generate_keys base_point a b p n in
          Printf.printf "ECC Public key: %s\n"
            (ECC.point_to_string keys.public_key);
          Printf.printf "ECC Private key: %d\n" keys.private_key;

          let encrypted_message =
            encrypt_message_ecc message_ascii base_point keys.ECC.public_key a b
              p n
          in
          let encrypted_filename = filename ^ ".enc.ecc" in
          let encrypted_content =
            String.concat "\n"
              (List.map
                 (fun (c1, c2) ->
                   match (c1, c2) with
                   | ECC.Point (x1, y1), ECC.Point (x2, y2) ->
                       Printf.sprintf "%d,%d,%d,%d" x1 y1 x2 y2
                   | ECC.Point (x1, y1), Infinity ->
                       Printf.sprintf "%d,%d,inf,inf" x1 y1
                   | Infinity, ECC.Point (x2, y2) ->
                       Printf.sprintf "inf,inf,%d,%d" x2 y2
                   | Infinity, Infinity -> "inf,inf,inf,inf")
                 encrypted_message)
          in

          write_to_file encrypted_filename encrypted_content;
          Printf.printf "Encrypted file saved as: %s\n" encrypted_filename
      | None -> Printf.printf "Failed to read the file.\n")
  | "2" -> (
      Printf.printf "Enter the filename containing the encrypted message: ";
      let filename = read_line () in
      match read_file filename with
      | Some content -> (
          Printf.printf "Enter the private key: ";
          let private_key_input = read_line () in
          try
            let private_key = int_of_string private_key_input in

            let encrypted_message =
              List.filter_map
                (fun line ->
                  try
                    let trimmed_line = String.trim line in
                    Scanf.sscanf trimmed_line "%d,%d,%d,%d" (fun x1 y1 x2 y2 ->
                        Some (ECC.Point (x1, y1), ECC.Point (x2, y2)))
                  with _ -> None)
                (String.split_on_char '\n' content)
            in

            let a, b, p = (2, 3, 97) in
            let decrypted_message =
              decrypt_message_ecc encrypted_message private_key a p
            in

            let decrypted_filename = filename ^ ".dec" in
            write_to_file decrypted_filename decrypted_message;
            Printf.printf "Decrypted message saved as: %s\n" decrypted_filename
          with
          | Failure _ ->
              Printf.printf
                "Invalid private key format. Please enter a valid integer.\n"
          | _ ->
              Printf.printf
                "Failed to decrypt the message. Check the file format and key.\n"
          )
      | None -> Printf.printf "Failed to read the file.\n")
  | _ ->
      Printf.printf
        "Invalid operation for ECC. Please choose 1 for Encrypt or 2 for \
         Decrypt.\n"

(* SHA3/RC2 Functions *)
let encrypt_message_sha3_rc2 filename content =
  let key = filename in
  Printf.printf "Using key (derived from filename): %s\n" key;
  let encrypted = Encryptor.Sha3.encrypt_rc2_sha3 key content in
  encrypted

let decrypt_message_sha3_rc2 filename encrypted_content =
  let key = filename in
  Printf.printf "Using key (derived from filename): %s\n" key;
  let decrypted = Encryptor.Sha3.decrypt_rc2_sha3 key encrypted_content in
  decrypted

let sha3_workflow () =
  Printf.printf "Choose operation: 1 for Encrypt, 2 for Decrypt: ";
  let operation = read_line () in
  match operation with
  | "1" -> (
      (* Encryption Workflow *)
      Printf.printf "Enter the filename containing the message to encrypt: ";
      let filename = read_line () in
      match read_file filename with
      | Some content ->
          let key = filename in
          Printf.printf "Using key (derived from filename): %s\n" key;

          let encrypted_message = Encryptor.Sha3.encrypt_rc2_sha3 key content in

          let encrypted_filename = filename ^ ".enc.sha" in
          write_to_file encrypted_filename encrypted_message;
          Printf.printf "Encrypted file saved as: %s\n" encrypted_filename
      | None -> Printf.printf "Failed to read the file.\n")
  | "2" -> (
      (* Decryption Workflow *)
      Printf.printf "Enter the filename containing the encrypted message: ";
      let filename = read_line () in
      match read_file filename with
      | Some encrypted_content ->
          let key = filename in
          Printf.printf "Using key (derived from filename): %s\n" key;

          let decrypted_message =
            Encryptor.Sha3.decrypt_rc2_sha3 key encrypted_content
          in

          let decrypted_filename = filename ^ ".dec" in
          write_to_file decrypted_filename decrypted_message;
          Printf.printf "Decrypted file saved as: %s\n" decrypted_filename
      | None -> Printf.printf "Failed to read the file.\n")
  | _ ->
      Printf.printf
        "Invalid operation for SHA3. Please choose 1 for Encrypt or 2 for \
         Decrypt.\n"

(* Blowfish Workflow *)
let blowfish_workflow () =
  Printf.printf "Choose operation: 1 for Encrypt, 2 for Decrypt: ";
  let operation = read_line () in
  match operation with
  | "1" ->
      Printf.printf "Enter the filename containing the message to encrypt: ";
      let filename = read_line () in
      Printf.printf "Enter the numeric key (8 digits) for Blowfish: ";
      let key = int_of_string (read_line ()) in
      encrypt_file_blowfish filename key;
      Printf.printf "File encryption completed.\n"
  | "2" ->
      Printf.printf "Enter the filename containing the message to decrypt: ";
      let filename = read_line () in
      Printf.printf "Enter the numeric key (8 digits) for Blowfish: ";
      let key = int_of_string (read_line ()) in
      decrypt_file_blowfish filename key;
      Printf.printf "File decryption completed.\n"
  | _ -> Printf.printf "Invalid operation for Blowfish.\n"

(* RSA Workflow *)
let rsa_workflow () =
  Printf.printf "Choose operation: 1 for Encrypt, 2 for Decrypt: ";
  match read_line () with
  | "1" ->
      Printf.printf
        "Do you want to use an existing public key or generate a new one?\n";
      Printf.printf "1. Use existing public key\n";
      Printf.printf "2. Generate new keys\n";
      let encrypt_choice = read_line () in
      if encrypt_choice = "1" then (
        Printf.printf "Enter the filename containing the message to encrypt: ";
        let filename = read_line () in
        Printf.printf "Enter the public key (e, n): ";
        match read_line () with
        | input -> (
            try
              let e, n = Scanf.sscanf input "%d %d" (fun e n -> (e, n)) in
              match read_file filename with
              | Some content ->
                  let message_ascii =
                    List.map Char.code (List.of_seq (String.to_seq content))
                  in
                  let encrypted_message =
                    List.map (fun m -> Rsa.rsa_encrypt m (e, n)) message_ascii
                  in
                  let encrypted_filename = filename ^ ".enc.rsa" in
                  let encrypted_content =
                    String.concat " " (List.map string_of_int encrypted_message)
                  in
                  write_to_file encrypted_filename encrypted_content;
                  Printf.printf "Encrypted file saved as: %s\n"
                    encrypted_filename
              | None -> Printf.printf "Failed to read the file.\n"
            with _ ->
              Printf.printf
                "Invalid key format. Use 'e n' format (e.g., 17 3233).\n"))
      else if encrypt_choice = "2" then (
        Printf.printf "Enter the filename containing the message to encrypt: ";
        let filename = read_line () in
        match read_file filename with
        | Some content ->
            let public_key, private_key = Rsa.generate_keys () in
            Printf.printf "Public Key (e, n): (%d, %d)\n" (fst public_key)
              (snd public_key);
            Printf.printf
              "Private Key (d, n): (%d, %d). Keep this key secure!\n"
              (fst private_key) (snd private_key);

            let message_ascii =
              List.map Char.code (List.of_seq (String.to_seq content))
            in
            let encrypted_message =
              List.map (fun m -> Rsa.rsa_encrypt m public_key) message_ascii
            in
            let encrypted_filename = filename ^ ".enc.rsa" in
            let encrypted_content =
              String.concat " " (List.map string_of_int encrypted_message)
            in
            write_to_file encrypted_filename encrypted_content;
            Printf.printf "Encrypted file saved as: %s\n" encrypted_filename
        | None -> Printf.printf "Failed to read the file.\n")
      else Printf.printf "Invalid choice for encryption.\n"
  | "2" -> (
      Printf.printf "Enter the filename containing the encrypted message: ";
      let filename = read_line () in
      Printf.printf "Enter the private key (d, n): ";
      match read_line () with
      | input -> (
          try
            let d, n = Scanf.sscanf input "%d %d" (fun d n -> (d, n)) in
            match read_file filename with
            | Some encrypted_content ->
                let encrypted_message =
                  List.map int_of_string
                    (String.split_on_char ' ' encrypted_content)
                in
                let decrypted_ascii =
                  List.map (fun c -> Rsa.rsa_decrypt c (d, n)) encrypted_message
                in
                let decrypted_message =
                  String.of_seq
                    (List.to_seq (List.map Char.chr decrypted_ascii))
                in
                let decrypted_filename = filename ^ ".dec" in
                write_to_file decrypted_filename decrypted_message;
                Printf.printf "Decrypted file saved as: %s\n" decrypted_filename
            | None -> Printf.printf "Failed to read the file.\n"
          with _ ->
            Printf.printf
              "You either used the incorrect key or you inputted an invalid \
               key format. Use 'd n' format (e.g., 413 3233).\n"))
  | _ -> Printf.printf "Invalid operation for RSA.\n"

(* AES-128 Workflow *)
let aes128_workflow () =
  Printf.printf "Choose operation: 1 for Encrypt, 2 for Decrypt: ";
  let operation = read_line () in
  Printf.printf "Enter the filename: ";
  let filename = read_line () in
  Printf.printf "Enter the AES-128 Key (16 Characters): ";
  let key = read_line () in
  if String.length key <> 16 then (
    Printf.printf "Error: Key must be exactly 16 characters.\n";
    exit 1);
  match operation with
  | "1" -> encrypt_file filename key
  | "2" -> decrypt_file filename key
  | _ ->
      Printf.printf
        "Invalid option. Please select (1) to Encrypt or (2) to Decrypt.\n";
      exit 1

(* Main Driver Program *)
let rsa_ecc_aes_workflow () =
  let method_choice = ask_for_method () in
  match method_choice with
  | `RSA -> rsa_workflow ()
  | `Blowfish -> blowfish_workflow ()
  | `ECC -> ecc_workflow ()
  | `SHA3 -> sha3_workflow ()
  | `AES128 -> aes128_workflow ()
  | _ -> Printf.printf "Invalid method selected.\n"

let () =
  match Array.to_list Sys.argv with
  | [ _; "encryptor" ] -> rsa_ecc_aes_workflow ()
  | _ ->
      Printf.printf "Usage:\n";
      Printf.printf "  Encryption Workflow: %s encryptor\n" Sys.argv.(0)
