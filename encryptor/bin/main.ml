(* bin/main.ml *)
open Lib
open Rsa

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

(* Function to encrypt a message (a list of ASCII codes) *)
let encrypt_message message (e, n) =
  List.map (fun m -> Rsa.rsa_encrypt m (e, n)) message

(* Function to decrypt a message (a list of encrypted integers) *)
let decrypt_message ciphertext (d, n) =
  List.map (fun c -> Rsa.rsa_decrypt c (d, n)) ciphertext

(* Main function to ask the user for a file and encrypt its contents *)
let ask_for_file () =
  Printf.printf "Enter the filename containing the message to encrypt: ";
  let filename = read_line () in
  match read_file filename with
  | Some content ->
      (* Generate RSA keys *)
      let public_key, private_key = Rsa.generate_keys () in
      Printf.printf "Public key: (e = %d, n = %d)\n" (fst public_key)
        (snd public_key);
      Printf.printf "Private key: (d = %d, n = %d)\n" (fst private_key)
        (snd private_key);

      (* Convert the message to ASCII codes *)
      let message_ascii = string_to_ascii content in
      Printf.printf "Message as ASCII codes: %s\n"
        (String.concat ", " (List.map string_of_int message_ascii));

      (* Encrypt the message *)
      let encrypted_message = encrypt_message message_ascii public_key in
      Printf.printf "Encrypted message: %s\n"
        (String.concat ", " (List.map string_of_int encrypted_message));

      (* Decrypt the message *)
      let decrypted_ascii = decrypt_message encrypted_message private_key in
      let decrypted_message = ascii_to_string decrypted_ascii in
      Printf.printf "Decrypted message: %s\n" decrypted_message
  | None -> Printf.printf "Failed to read the file.\n"

(* Entry point of the program *)
let () = ask_for_file ()
