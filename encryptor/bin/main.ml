open Encryptor.Rsa
open Encryptor.Ecc
open Encryptor.Util

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

(* Function to convert string to ASCII codes *)
let string_to_ascii message =
  List.map Char.code (List.of_seq (String.to_seq message))

(* Function to convert ASCII codes back to a string *)
let ascii_to_string ascii_codes =
  String.of_seq (List.to_seq (List.map Char.chr ascii_codes))

(* RSA Functions *)
let encrypt_message_rsa message (e, n) =
  List.map (fun m -> Rsa.rsa_encrypt m (e, n)) message

let decrypt_message_rsa ciphertext (d, n) =
  List.map (fun c -> Rsa.rsa_decrypt c (d, n)) ciphertext

(* ECC Functions *)
let encrypt_message_ecc message base_point public_key a b p n =
  List.map (fun m -> ECC.encrypt m base_point public_key a b p n) message

let decrypt_message_ecc ciphertext private_key a p =
  List.map (fun (c1, c2) -> ECC.decrypt (c1, c2) private_key a p) ciphertext

(* Ask the user for encryption method *)
let ask_for_method () =
  Printf.printf "Choose an encryption method:\n";
  Printf.printf "1. RSA\n";
  Printf.printf "2. ECC\n";
  Printf.printf "Enter your choice: ";
  match read_line () with
  | "1" -> `RSA
  | "2" -> `ECC
  | _ -> failwith "Invalid choice"

(* Main function to ask the user for a file and encrypt its contents *)
let ask_for_file () =
  let method_choice = ask_for_method () in
  Printf.printf "Enter the filename containing the message to encrypt: ";
  let filename = read_line () in
  match read_file filename with
  | Some content -> (
      let message_ascii = string_to_ascii content in
      Printf.printf "Message as ASCII codes: %s\n"
        (String.concat ", " (List.map string_of_int message_ascii));

      match method_choice with
      | `RSA ->
          (* RSA Key Generation *)
          let public_key, private_key = Rsa.generate_keys () in
          Printf.printf "RSA Public key: (e = %d, n = %d)\n" (fst public_key)
            (snd public_key);
          Printf.printf "RSA Private key: (d = %d, n = %d)\n" (fst private_key)
            (snd private_key);

          (* Encrypt and Decrypt using RSA *)
          let encrypted_message =
            encrypt_message_rsa message_ascii public_key
          in
          Printf.printf "Encrypted message: %s\n"
            (String.concat ", " (List.map string_of_int encrypted_message));

          let decrypted_ascii =
            decrypt_message_rsa encrypted_message private_key
          in
          let decrypted_message = ascii_to_string decrypted_ascii in
          Printf.printf "Decrypted message: %s\n" decrypted_message
      | `ECC ->
          (* ECC Key Generation *)
          let base_point = ECC.Point (3, 6) in
          let a, b, p, n = (2, 3, 97, 5) in
          let keys = ECC.generate_keys base_point a b p n in
          Printf.printf "ECC Public key: %s\n"
            (ECC.point_to_string keys.public_key);
          Printf.printf "ECC Private key: %d\n" keys.private_key;

          (* Encrypt and Decrypt using ECC *)
          let encrypted_message =
            encrypt_message_ecc message_ascii base_point keys.ECC.public_key a b
              p n
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
          let decrypted_message = ascii_to_string decrypted_ascii in
          Printf.printf "Decrypted message: %s\n" decrypted_message)
  | None -> Printf.printf "Failed to read the file.\n"

(* Previous functions remain the same *)
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

(* Other existing functions remain unchanged *)
let string_to_ascii message =
  List.map Char.code (List.of_seq (String.to_seq message))

let ascii_to_string ascii_codes =
  String.of_seq (List.to_seq (List.map Char.chr ascii_codes))

let encrypt_message message (e, n) =
  List.map (fun m -> Rsa.rsa_encrypt m (e, n)) message

let decrypt_message ciphertext (d, n) =
  List.map (fun c -> Rsa.rsa_decrypt c (d, n)) ciphertext

let ask_for_file () =
  (* Your existing interactive RSA function *)
  Printf.printf "Enter the filename containing the message to encrypt: ";
  let filename = read_line () in
  match read_file filename with
  | Some content ->
      let public_key, private_key = Rsa.generate_keys () in
      Printf.printf "Public key: (e = %d, n = %d)\n" (fst public_key)
        (snd public_key);
      Printf.printf "Private key: (d = %d, n = %d)\n" (fst private_key)
        (snd private_key);

      let message_ascii = string_to_ascii content in
      Printf.printf "Message as ASCII codes: %s\n"
        (String.concat ", " (List.map string_of_int message_ascii));

      let encrypted_message = encrypt_message message_ascii public_key in
      Printf.printf "Encrypted message: %s\n"
        (String.concat ", " (List.map string_of_int encrypted_message));

      let decrypted_ascii = decrypt_message encrypted_message private_key in
      let decrypted_message = ascii_to_string decrypted_ascii in
      Printf.printf "Decrypted message: %s\n" decrypted_message
  | None -> Printf.printf "Failed to read the file.\n"

let display_file_contents filename =
  try
    let ic = open_in_bin filename in
    (* Using binary mode to handle encrypted files *)
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    Printf.printf "\nContents of %s (%d bytes):\n%s\n" filename
      (String.length content) content
  with _ -> Printf.printf "\nCould not read contents of %s\n" filename

let () =
  match Sys.argv with
  | [| _; "rsa" |] -> ask_for_file () (* Original RSA functionality *)
  | [| _; "sha3"; "encrypt"; filename |] ->
      Printf.printf "\nOriginal file contents:\n";
      display_file_contents filename;

      if Encryptor.Sha3.encrypt filename then (
        Printf.printf "\nFile encrypted successfully to %s.enc\n" filename;
        Printf.printf "\nEncrypted file contents:\n";
        display_file_contents (filename ^ ".enc"))
      else Printf.printf "SHA3/RC2 encryption failed\n"
  | [| _; "sha3"; "decrypt"; filename |] ->
      Printf.printf "\nEncrypted file contents:\n";
      display_file_contents filename;

      if Encryptor.Sha3.decrypt filename then (
        let original_filename = Filename.chop_suffix filename ".enc" in
        Printf.printf "\nFile decrypted successfully to %s.dec\n"
          original_filename;
        Printf.printf "\nDecrypted file contents:\n";
        display_file_contents (original_filename ^ ".dec"))
      else Printf.printf "SHA3/RC2 decryption failed\n"
  | _ ->
      Printf.printf "Usage:\n";
      Printf.printf "  RSA: %s rsa\n" Sys.argv.(0);
      Printf.printf "  SHA3/RC2: %s sha3 <encrypt|decrypt> <filename>\n"
        Sys.argv.(0)
