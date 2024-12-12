open Encryptor.Rsa
open Encryptor.Ecc
open Encryptor.Util
open Encryptor.Sha3
open Encryptor.Aes128
open Encryptor.Blowfish

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

let ask_for_method () =
  Printf.printf "Choose an encryption method:\n";
  Printf.printf "1. RSA\n";
  Printf.printf "2. ECC\n";
  Printf.printf "3. SHA3/RC2\n";
  Printf.printf "4. AES-128\n";
  Printf.printf "5. Blowfish\n";
  Printf.printf "Enter your choice: ";
  match read_line () with
  | "1" -> `RSA
  | "2" -> `ECC
  | "3" -> `SHA3
  | "4" -> `AES128
  | "5" -> `Blowfish
  | _ -> failwith "Invalid choice"

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
                  let encrypted_filename = filename ^ ".enc" in
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
            let encrypted_filename = filename ^ ".enc" in
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

(* ECC Functions 2042981, 4099343 *)
let encrypt_message_ecc message base_point public_key a b p n =
  List.map (fun m -> ECC.encrypt m base_point public_key a b p n) message

let decrypt_message_ecc ciphertext private_key a p =
  List.map (fun (c1, c2) -> ECC.decrypt (c1, c2) private_key a p) ciphertext

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

(* Other Algorithms (AES, SHA3/RC2, ECC) *)
let other_workflows method_choice filename content =
  match method_choice with
  | `AES128 ->
      let key = "examplekey123456" in
      Printf.printf "AES-128 Key: %s\n" key;
      let encrypted_message = Encryptor.Aes128.encrypt content key in
      Printf.printf "Encrypted message: %s\n" encrypted_message;

      let decrypted_message = Encryptor.Aes128.decrypt encrypted_message key in
      Printf.printf "Decrypted message: %s\n" decrypted_message
  | `SHA3 ->
      let encrypted_message = encrypt_message_sha3_rc2 filename content in
      Printf.printf "Encrypted message: %s\n" encrypted_message;

      let decrypted_message =
        decrypt_message_sha3_rc2 filename encrypted_message
      in
      Printf.printf "Decrypted message: %s\n" decrypted_message
  | `ECC ->
      let base_point = ECC.Point (3, 6) in
      let a, b, p, n = (2, 3, 97, 5) in
      let keys = ECC.generate_keys base_point a b p n in
      Printf.printf "ECC Public key: %s\n" (ECC.point_to_string keys.public_key);
      Printf.printf "ECC Private key: %d\n" keys.private_key;

      let message_ascii =
        List.map Char.code (List.of_seq (String.to_seq content))
      in
      let encrypted_message =
        encrypt_message_ecc message_ascii base_point keys.ECC.public_key a b p n
      in
      Printf.printf "Encrypted message: %s\n"
        (String.concat ", "
           (List.map
              (fun (c1, c2) ->
                Printf.sprintf "(%s, %s)" (ECC.point_to_string c1)
                  (ECC.point_to_string c2))
              encrypted_message));

      let decrypted_ascii =
        decrypt_message_ecc encrypted_message keys.ECC.private_key a p
      in
      let decrypted_message =
        String.of_seq (List.to_seq (List.map Char.chr decrypted_ascii))
      in
      Printf.printf "Decrypted message: %s\n" decrypted_message
  | _ -> Printf.printf "Invalid method selected.\n"

(* Main Driver Program *)
let rsa_ecc_aes_workflow () =
  let method_choice = ask_for_method () in
  match method_choice with
  | `RSA -> rsa_workflow ()
  | `Blowfish -> blowfish_workflow ()
  | _ -> (
      Printf.printf "Enter the filename containing the message: ";
      let filename = read_line () in
      match read_file filename with
      | Some content -> other_workflows method_choice filename content
      | None -> Printf.printf "Failed to read the file.\n")

let () =
  match Array.to_list Sys.argv with
  | [ _; "encryptor" ] -> rsa_ecc_aes_workflow ()
  | _ ->
      Printf.printf "Usage:\n";
      Printf.printf "  Encryption Workflow: %s encryptor\n" Sys.argv.(0)
