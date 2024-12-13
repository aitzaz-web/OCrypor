open OUnit2
open Encryptor.Aes128

let test_pad_block_1 _ =
  let str = "" in
  assert_equal (pad_block str)
    "\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016"

let test_pad_block_2 _ =
  let str = "abcdefghijklmnop" in
  assert_equal (pad_block str) "abcdefghijklmnop"

let test_split_into_blocks_encrypt_1 _ =
  let str = "abcdefghijklmnop" in
  assert_equal (split_into_blocks_encrypt str) [ "abcdefghijklmnop" ]

let test_split_into_blocks_encrypt_2 _ =
  let str = "abcdefghijklmnopqrstuvwxyz" in
  assert_equal
    (split_into_blocks_encrypt str)
    [ "abcdefghijklmnop"; "qrstuvwxyz\006\006\006\006\006\006" ]

let test_split_into_blocks_encrypt_3 _ =
  let str = "" in
  assert_equal (split_into_blocks_encrypt str) []

let test_string_to_state_1 _ =
  let str = "abcdefghijklmnop" in
  let actual = string_to_state str in
  let expected =
    [|
      [| 97; 98; 99; 100 |];
      [| 101; 102; 103; 104 |];
      [| 105; 106; 107; 108 |];
      [| 109; 110; 111; 112 |];
    |]
  in

  (* Print actual and expected for debugging *)
  Printf.printf "Expected:\n";
  Array.iter
    (fun row ->
      Array.iter (Printf.printf "%d ") row;
      Printf.printf "\n")
    expected;

  Printf.printf "Actual:\n";
  Array.iter
    (fun row ->
      Array.iter (Printf.printf "%d ") row;
      Printf.printf "\n")
    actual;

  assert_equal expected actual

let test_string_to_state_2 _ =
  let str = "aes128issocool!!" in
  assert_equal (string_to_state str)
    [|
      [| 97; 101; 115; 49 |];
      [| 50; 56; 105; 115 |];
      [| 115; 111; 99; 111 |];
      [| 111; 108; 33; 33 |];
    |]

let test_sub_bytes_1 _ =
  let state =
    [|
      [| 0x32; 0x7C; 0x63; 0x01 |];
      [| 0xF2; 0x6B; 0x6F; 0xC5 |];
      [| 0x30; 0x67; 0x2B; 0xFE |];
      [| 0xD7; 0xAB; 0x76; 0xCA |];
    |]
  in
  let expected =
    [|
      [| s_box.(0x32); s_box.(0x7C); s_box.(0x63); s_box.(0x01) |];
      [| s_box.(0xF2); s_box.(0x6B); s_box.(0x6F); s_box.(0xC5) |];
      [| s_box.(0x30); s_box.(0x67); s_box.(0x2B); s_box.(0xFE) |];
      [| s_box.(0xD7); s_box.(0xAB); s_box.(0x76); s_box.(0xCA) |];
    |]
  in
  assert_equal (sub_bytes state) expected

let test_inv_sub_bytes_1 _ =
  let state =
    [|
      [| s_box.(0x32); s_box.(0x7C); s_box.(0x63); s_box.(0x01) |];
      [| s_box.(0xF2); s_box.(0x6B); s_box.(0x6F); s_box.(0xC5) |];
      [| s_box.(0x30); s_box.(0x67); s_box.(0x2B); s_box.(0xFE) |];
      [| s_box.(0xD7); s_box.(0xAB); s_box.(0x76); s_box.(0xCA) |];
    |]
  in
  let expected =
    [|
      [| 0x32; 0x7C; 0x63; 0x01 |];
      [| 0xF2; 0x6B; 0x6F; 0xC5 |];
      [| 0x30; 0x67; 0x2B; 0xFE |];
      [| 0xD7; 0xAB; 0x76; 0xCA |];
    |]
  in
  assert_equal (inv_sub_bytes state) expected

let test_shift_rows_1 _ =
  let state =
    [|
      [| 1; 2; 3; 4 |];
      [| 5; 6; 7; 8 |];
      [| 9; 10; 11; 12 |];
      [| 13; 14; 15; 16 |];
    |]
  in
  let expected =
    [|
      [| 1; 2; 3; 4 |];
      [| 6; 7; 8; 5 |];
      [| 11; 12; 9; 10 |];
      [| 16; 13; 14; 15 |];
    |]
  in
  assert_equal (shift_rows state) expected

let test_shift_rows_2 _ =
  let state =
    [|
      [| 0xd4; 0xe0; 0xb8; 0x1e |];
      [| 0x27; 0xbf; 0xb4; 0x41 |];
      [| 0x11; 0x98; 0x5d; 0x52 |];
      [| 0xae; 0xf1; 0xe5; 0x30 |];
    |]
  in
  let expected =
    [|
      [| 0xd4; 0xe0; 0xb8; 0x1e |];
      [| 0xbf; 0xb4; 0x41; 0x27 |];
      [| 0x5d; 0x52; 0x11; 0x98 |];
      [| 0x30; 0xae; 0xf1; 0xe5 |];
    |]
  in
  assert_equal (shift_rows state) expected

let test_inv_shift_rows_1 _ =
  let state =
    [|
      [| 1; 2; 3; 4 |];
      [| 6; 7; 8; 5 |];
      [| 11; 12; 9; 10 |];
      [| 16; 13; 14; 15 |];
    |]
  in
  let expected =
    [|
      [| 1; 2; 3; 4 |];
      [| 5; 6; 7; 8 |];
      [| 9; 10; 11; 12 |];
      [| 13; 14; 15; 16 |];
    |]
  in
  assert_equal (inv_shift_rows state) expected

let test_transpose _ =
  (* Test 1: Transposing a rectangular matrix *)
  let matrix1 = [| [| 1; 2; 3 |]; [| 4; 5; 6 |] |] in
  let expected1 = [| [| 1; 4 |]; [| 2; 5 |]; [| 3; 6 |] |] in
  assert_equal expected1 (transpose matrix1)

let test_gmul_1 _ = assert_equal (gmul 87 131) 193
let test_gmul_2 _ = assert_equal (gmul 87 2) 174

let test_gmul_cases _ =
  assert_equal (gmul 0x57 0x83) 0xc1;
  (* Example from AES specification *)
  assert_equal (gmul 0x57 0x01) 0x57;
  (* Multiplication with 1 (identity) *)
  assert_equal (gmul 0x57 0x02) 0xae;
  (* Multiplication with 2 *)
  assert_equal (gmul 0x57 0x03) 0xf9;
  (* Multiplication with 3 (2 XOR 1) *)
  assert_equal (gmul 0x80 0x02) 0x1b;

  (* Example involving modulo reduction *)
  Printf.printf "gmul tests passed.\n"

let test_all_mix_columns_inverse _ =
  (* Generate a 4x4 matrix with values 1-16 *)
  let original_state =
    [|
      [| 0x01; 0x02; 0x03; 0x04 |];
      [| 0x05; 0x06; 0x07; 0x08 |];
      [| 0x09; 0x0A; 0x0B; 0x0C |];
      [| 0x0D; 0x0E; 0x0F; 0x10 |];
    |]
  in

  (* Apply MixColumns and then InvMixColumns *)
  let after_mix = mix_columns original_state in
  let after_inv_mix = inv_mix_columns after_mix in

  (* Check if the resulting state matches the original state *)
  assert_equal original_state after_inv_mix;
  (* Test passed if assert passes *)
  Printf.printf
    "MixColumns and InvMixColumns work correctly as inverses for the 1-16 \
     matrix.\n"

let get_data_file filename =
  Filename.concat (Sys.getcwd ()) ("../data/" ^ filename)

let list_sub lst start len =
  lst
  |> List.mapi (fun i x -> (i, x))
  |> List.filter (fun (i, _) -> i >= start && i < start + len)
  |> List.map snd

let csv_to_3d_array filename =
  let filepath = get_data_file filename in
  let lines = Csv.load filepath in
  let round_keys =
    List.map
      (fun line ->
        let values = List.map int_of_string line in
        Array.init 4 (fun i -> Array.of_list (list_sub values (i * 4) 4)))
      lines
  in
  Array.of_list round_keys

let test_key_expansion _ =
  let key = "abcdefghabcdefghi" in
  let expanded_keys = key_expansion key in

  (* Load the expected keys from the CSV file *)
  let expected_keys = csv_to_3d_array "test_key_expansion_expected.csv" in

  (* Validate the number of expanded keys *)
  assert_equal (Array.length expanded_keys) (Array.length expected_keys);

  (* Print both the generated keys and the expected keys *)
  Array.iteri
    (fun i round_key ->
      (* Validate the current round key *)
      assert_equal round_key expected_keys.(i))
    expanded_keys;

  Printf.printf "Key expansion test passed.\n"

let test_aes_encrypt_block _ =
  let key = "abcdefghabcdefghi" in
  (* 16-byte key *)
  let round_keys = key_expansion key in
  let block = "abcdefghabcdefghi" in

  (* 16-byte block *)
  let encrypted_block = aes_encrypt_block block round_keys in

  (* Check that the encrypted block is not the same as the original block *)
  assert (encrypted_block <> block);

  (* Test passed *)
  Printf.printf "AES block encryption test passed.\n"

let test_aes_decrypt_block _ =
  let key = "imonlyhumanafter" in
  (* 16-byte key *)
  let round_keys = key_expansion key in
  let block = "abcdefghijklmnop" in

  (* 16-byte block *)

  (* Encrypt the block *)
  let encrypted_block = aes_encrypt_block block round_keys in
  Printf.printf "Encrypted block: ";
  String.iter (fun c -> Printf.printf "%02x " (Char.code c)) encrypted_block;
  Printf.printf "\n";

  (* Decrypt the block *)
  let decrypted_block = aes_decrypt_block encrypted_block round_keys in
  Printf.printf "Decrypted block: %s\n" decrypted_block;

  (* Ensure that decrypting the encrypted block returns the original block *)
  assert_equal decrypted_block block;

  (* Test passed *)
  Printf.printf "AES block decryption test passed.\n"

let test_encrypt _ =
  let key = "imonlyhumanafter" in
  (* 16-byte key *)
  let message = "abcdefghabcdefghi" in

  (* 16-byte message *)
  let encrypted_message = encrypt message key in

  (* Print the encrypted message in hexadecimal format *)
  Printf.printf "Encrypted message: ";
  String.iter (fun c -> Printf.printf "%02x " (Char.code c)) encrypted_message;
  Printf.printf "\n";

  (* Ensure that encryption produces a different output *)
  assert (encrypted_message <> message);

  (* Test passed *)
  Printf.printf "Encryption test passed.\n"

let test_decrypt _ =
  let key = "wowthisissocool!" in
  (* 16-byte key *)
  let message = "abcdefghijklmnopqrstuvwxyz" in

  (* 16-byte message *)

  (* Encrypt the message first *)
  let encrypted_message = encrypt message key in

  (* Now decrypt the message *)
  let decrypted_message = decrypt encrypted_message key in

  (* Print the decrypted message *)
  Printf.printf "Decrypted message: %s\n" decrypted_message;

  (* Ensure that decryption returns the original message *)
  assert_equal decrypted_message message;

  (* Test passed *)
  Printf.printf "Decryption test passed.\n"

let ensure_data_directory_exists () =
  if not (Sys.file_exists "data") then Sys.mkdir "data" 0o755

let test_encrypt_file_creates_file _ =
  (* Ensure the data directory exists *)
  ensure_data_directory_exists ();

  (* Test inputs *)
  let test_filename = "testfile.txt" in
  let test_key = "mysecretkey12345" in

  (* Create a sample file in the data directory for the test *)
  let test_file_path = Filename.concat "data" test_filename in
  let oc = open_out_bin test_file_path in
  output_string oc "This is a test file.";
  close_out oc;

  (* Call the encrypt_file function *)
  encrypt_file test_filename test_key;

  (* Verify the encrypted file exists *)
  let encrypted_file_path = Filename.concat "data" (test_filename ^ ".enc") in
  assert (Sys.file_exists encrypted_file_path);

  (* Clean up created files *)
  Sys.remove test_file_path;
  Sys.remove encrypted_file_path;

  Printf.printf "test_encrypt_file_creates_file passed.\n"

let test_encrypt_decrypt_file _ =
  (* Ensure the data directory exists *)
  ensure_data_directory_exists ();

  (* Test inputs *)
  let test_filename = "testfile.txt" in
  let test_key = "mysecretkey12345" in
  let original_content = "This is a test file." in

  (* File paths *)
  let test_file_path = Filename.concat "data" test_filename in
  let encrypted_file_path = Filename.concat "data" (test_filename ^ ".enc") in
  let decrypted_file_path = Filename.concat "data" (test_filename ^ ".dec") in

  (* Helper function to read file content *)
  let read_file_content path =
    let ic = open_in_bin path in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    content
  in

  (* Helper function to clean up test files *)
  let clean_test_files () =
    List.iter
      (fun path ->
        if Sys.file_exists path then (
          Printf.printf "Removing file: %s\n" path;
          Sys.remove path))
      [ test_file_path; encrypted_file_path; decrypted_file_path ]
  in

  (* Clean up any leftover files before starting the test *)
  Printf.printf "Cleaning up any leftover files...\n";
  clean_test_files ();

  (* Step 1: Create the test file *)
  Printf.printf "Creating test file: %s\n" test_file_path;
  let oc = open_out_bin test_file_path in
  output_string oc original_content;
  close_out oc;
  Printf.printf "Test file created with content: %s\n" original_content;

  (* Step 2: Encrypt the test file *)
  Printf.printf "Encrypting file: %s\n" test_file_path;
  encrypt_file test_filename test_key;

  (* Step 3: Verify the encrypted file exists *)
  if Sys.file_exists encrypted_file_path then
    Printf.printf "Encrypted file created: %s\n" encrypted_file_path
  else (
    Printf.printf "Encrypted file not found: %s\n" encrypted_file_path;
    assert false);

  (* Step 4: Read and print the encrypted file content *)
  let encrypted_content = read_file_content encrypted_file_path in
  Printf.printf "Encrypted content (hex): ";
  String.iter (fun c -> Printf.printf "%02x " (Char.code c)) encrypted_content;
  Printf.printf "\n";

  (* Step 5: Decrypt the encrypted file *)
  Printf.printf "Expected decrypted file path: %s\n" decrypted_file_path;
  decrypt_file (test_filename ^ ".enc") test_key;

  (* Step 6: Verify the decrypted file exists *)
  if Sys.file_exists decrypted_file_path then
    Printf.printf "Decrypted file created: %s\n" decrypted_file_path
  else (
    Printf.printf "Decrypted file not found: %s\n" decrypted_file_path;
    assert false);

  (* Step 7: Read and print the decrypted file content *)
  let decrypted_content = read_file_content decrypted_file_path in
  Printf.printf "Decrypted content: %s\n" decrypted_content;
  flush stdout;

  (* Step 8: Compare original content with decrypted content *)
  Printf.printf "Original content: %s\n" original_content;
  assert_equal original_content decrypted_content;

  (* Step 9: Clean up created files after the test *)
  Printf.printf "Cleaning up test files...\n";
  clean_test_files ();

  Printf.printf "test_encrypt_decrypt_file passed.\n"

let tests =
  "test suite"
  >::: [
         "test_pad_block_1" >:: test_pad_block_1;
         "test_pad_block_2" >:: test_pad_block_2;
         "test_split_into_blocks_1" >:: test_split_into_blocks_encrypt_1;
         "test_split_into_blocks_2" >:: test_split_into_blocks_encrypt_2;
         "test_split_into_blocks_3" >:: test_split_into_blocks_encrypt_3;
         "test_string_to_state_1" >:: test_string_to_state_1;
         "test_string_to_state_2" >:: test_string_to_state_2;
         "test_sub_bytes_1" >:: test_sub_bytes_1;
         "test_inv_sub_bytes_1" >:: test_inv_sub_bytes_1;
         "test_shift_rows_1" >:: test_shift_rows_1;
         "test_shift_rows_2" >:: test_shift_rows_2;
         "test_inv_shift_rows_1" >:: test_inv_shift_rows_1;
         "test_transpose" >:: test_transpose;
         "test_gmul_1" >:: test_gmul_1;
         "test_gmul_2" >:: test_gmul_2;
         "test_gmul_cases" >:: test_gmul_cases;
         "test_all_mix_columns_inverse" >:: test_all_mix_columns_inverse;
         "test_aes_encrypt_block" >:: test_aes_encrypt_block;
         "test_aes_decrypt_block" >:: test_aes_decrypt_block;
         "test_encrypt" >:: test_encrypt;
         "test_decrypt" >:: test_decrypt;
         "test_encrypt_decrypt_file" >:: test_encrypt_decrypt_file;
       ]

let _ = run_test_tt_main tests
