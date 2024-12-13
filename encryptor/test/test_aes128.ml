open OUnit2
open Encryptor.Aes128

(* [test_pad_block_1] tests the pad_block function for an empty string *)
let test_pad_block_1 _ =
  let str = "" in
  assert_equal (pad_block str)
    "\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016"

(* [test_pad_block_2] tests the pad_block function for a string with a length of
   16 *)
let test_pad_block_2 _ =
  let str = "abcdefghijklmnop" in
  assert_equal (pad_block str) "abcdefghijklmnop"

(* [test_split_into_blocks_encrypt_1] tests splitting a single 16-character
   block *)
let test_split_into_blocks_encrypt_1 _ =
  let str = "abcdefghijklmnop" in
  assert_equal (split_into_blocks_encrypt str) [ "abcdefghijklmnop" ]

(* [test_split_into_blocks_encrypt_2] tests splitting a string into multiple
   blocks with padding *)
let test_split_into_blocks_encrypt_2 _ =
  let str = "abcdefghijklmnopqrstuvwxyz" in
  assert_equal
    (split_into_blocks_encrypt str)
    [ "abcdefghijklmnop"; "qrstuvwxyz\006\006\006\006\006\006" ]

(* [test_split_into_blocks_encrypt_3] tests splitting an empty string *)
let test_split_into_blocks_encrypt_3 _ =
  let str = "" in
  assert_equal (split_into_blocks_encrypt str) []

(* [test_string_to_state_1] tests converting a string into a state matrix *)
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

(* [test_string_to_state_2] tests converting another string into a state
   matrix *)
let test_string_to_state_2 _ =
  let str = "aes128issocool!!" in
  assert_equal (string_to_state str)
    [|
      [| 97; 101; 115; 49 |];
      [| 50; 56; 105; 115 |];
      [| 115; 111; 99; 111 |];
      [| 111; 108; 33; 33 |];
    |]

(* [test_sub_bytes_1] tests the SubBytes transformation *)
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

(* [test_inv_sub_bytes_1] tests the inverse SubBytes transformation *)
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

(* [test_shift_rows_1] tests the ShiftRows transformation *)
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

(* [test_shift_rows_2] tests ShiftRows with a different state *)
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

(* [test_inv_shift_rows_1] tests the inverse ShiftRows transformation *)
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

(* [test_transpose] tests matrix transposition *)
let test_transpose _ =
  let matrix1 = [| [| 1; 2; 3 |]; [| 4; 5; 6 |] |] in
  let expected1 = [| [| 1; 4 |]; [| 2; 5 |]; [| 3; 6 |] |] in
  assert_equal expected1 (transpose matrix1)

(* [test_gmul_1] tests Galois Field multiplication for specific values *)
let test_gmul_1 _ = assert_equal (gmul 87 131) 193

(* [test_gmul_2] tests Galois Field multiplication with a small multiplier *)
let test_gmul_2 _ = assert_equal (gmul 87 2) 174

(* [test_gmul_cases] tests multiple Galois Field multiplication cases *)
let test_gmul_cases _ =
  assert_equal (gmul 0x57 0x83) 0xc1;
  assert_equal (gmul 0x57 0x01) 0x57;
  assert_equal (gmul 0x57 0x02) 0xae;
  assert_equal (gmul 0x57 0x03) 0xf9;
  assert_equal (gmul 0x80 0x02) 0x1b

(* [test_all_mix_columns_inverse] tests MixColumns and its inverse *)
let test_all_mix_columns_inverse _ =
  let original_state =
    [|
      [| 0x01; 0x02; 0x03; 0x04 |];
      [| 0x05; 0x06; 0x07; 0x08 |];
      [| 0x09; 0x0A; 0x0B; 0x0C |];
      [| 0x0D; 0x0E; 0x0F; 0x10 |];
    |]
  in
  let after_mix = mix_columns original_state in
  let after_inv_mix = inv_mix_columns after_mix in
  assert_equal original_state after_inv_mix

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

(* [test_aes_encrypt_block] tests that the AES encryption of a block changes the
   block content *)
let test_aes_encrypt_block _ =
  let key = "abcdefghabcdefghi" in
  let round_keys = key_expansion key in
  let block = "abcdefghabcdefghi" in
  let encrypted_block = aes_encrypt_block block round_keys in
  assert (encrypted_block <> block)

(* [test_aes_decrypt_block] tests that AES decryption restores the original
   block *)
let test_aes_decrypt_block _ =
  let key = "imonlyhumanafter" in
  let round_keys = key_expansion key in
  let block = "abcdefghijklmnop" in
  let encrypted_block = aes_encrypt_block block round_keys in
  let decrypted_block = aes_decrypt_block encrypted_block round_keys in
  assert_equal decrypted_block block

(* [test_encrypt] tests that the encrypt function alters the input message *)
let test_encrypt _ =
  let key = "imonlyhumanafter" in
  let message = "abcdefghabcdefghi" in
  let encrypted_message = encrypt message key in
  assert (encrypted_message <> message)

(* [test_decrypt] tests that the decrypt function restores the original
   message *)
let test_decrypt _ =
  let key = "wowthisissocool!" in
  let message = "abcdefghijklmnopqrstuvwxyz" in
  let encrypted_message = encrypt message key in
  let decrypted_message = decrypt encrypted_message key in
  assert_equal decrypted_message message

let ensure_data_directory_exists () =
  if not (Sys.file_exists "data") then Sys.mkdir "data" 0o755

(* [test_encrypt_file_creates_file] tests that encrypting a file generates an
   encrypted output file *)
let test_encrypt_file_creates_file _ =
  ensure_data_directory_exists ();
  let test_filename = "testfile.txt" in
  let test_key = "mysecretkey12345" in
  let test_file_path = Filename.concat "data" test_filename in
  let oc = open_out_bin test_file_path in
  output_string oc "This is a test file.";
  close_out oc;
  encrypt_file test_filename test_key;
  let encrypted_file_path = Filename.concat "data" (test_filename ^ ".enc") in
  assert (Sys.file_exists encrypted_file_path);
  Sys.remove test_file_path;
  Sys.remove encrypted_file_path

let test_encrypt_decrypt_file _ =
  ensure_data_directory_exists ();
  let test_filename = "data/testfile.txt" in
  let test_key = "mysecretkey12345" in
  let original_content = "This is a test file." in
  let test_file_path = test_filename in
  let encrypted_file_path = test_filename ^ ".enc" in
  let decrypted_file_path = test_filename ^ ".dec" in
  let read_file_content path =
    let ic = open_in_bin path in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    content
  in
  let clean_test_files () =
    List.iter
      (fun path ->
        if Sys.file_exists path then (
          Printf.printf "Removing file: %s\n" path;
          Sys.remove path))
      [ test_file_path; encrypted_file_path; decrypted_file_path ]
  in
  clean_test_files ();
  let oc = open_out_bin test_file_path in
  output_string oc original_content;
  close_out oc;
  encrypt_file test_file_path test_key;
  if Sys.file_exists encrypted_file_path then
    Printf.printf "Encrypted file created: %s\n" encrypted_file_path
  else (
    Printf.printf "Encrypted file not found: %s\n" encrypted_file_path;
    assert false);
  let encrypted_content = read_file_content encrypted_file_path in
  Printf.printf "Encrypted content (hex): ";
  String.iter (fun c -> Printf.printf "%02x " (Char.code c)) encrypted_content;
  Printf.printf "\n";
  Printf.printf "Expected decrypted file path: %s\n" decrypted_file_path;
  decrypt_file encrypted_file_path test_key;
  if Sys.file_exists decrypted_file_path then
    Printf.printf "Decrypted file created: %s\n" decrypted_file_path
  else (
    Printf.printf "Decrypted file not found: %s\n" decrypted_file_path;
    assert false);
  let decrypted_content = read_file_content decrypted_file_path in
  Printf.printf "Decrypted content: %s\n" decrypted_content;
  flush stdout;
  Printf.printf "Original content: %s\n" original_content;
  assert_equal original_content decrypted_content;
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
