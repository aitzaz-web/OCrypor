open OUnit2
open Encryptor.Aes128

let test_pad_block_1 _ =
  let str = "" in
  assert_equal (pad_block str)
    "\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016"

let test_pad_block_2 _ =
  let str = "abcdefghijklmnop" in
  assert_equal (pad_block str) "abcdefghijklmnop"

let test_split_into_blocks_1 _ =
  let str = "abcdefghijklmnop" in
  assert_equal (split_into_blocks str) [ "abcdefghijklmnop" ]

let test_split_into_blocks_2 _ =
  let str = "abcdefghijklmnopqrstuvwxyz" in
  assert_equal (split_into_blocks str)
    [ "abcdefghijklmnop"; "qrstuvwxyz\006\006\006\006\006\006" ]

let test_split_into_blocks_3 _ =
  let str = "" in
  assert_equal (split_into_blocks str) []

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

let test_key_expansion _ =
  let key = "abcdefghabcdefghi" in
  let expanded_keys = key_expansion key in

  (* Expected 11 round keys *)
  let expected_keys =
    [|
      [|
        [| 97; 98; 99; 100 |];
        [| 101; 102; 103; 104 |];
        [| 97; 98; 99; 100 |];
        [| 101; 102; 103; 104 |];
      |];
      [|
        [| 50; 132; 68; 76 |];
        [| 87; 226; 35; 36 |];
        [| 54; 128; 64; 64 |];
        [| 83; 230; 39; 40 |];
      |];
      [|
        [| 140; 206; 54; 239 |];
        [| 219; 44; 21; 203 |];
        [| 237; 172; 85; 139 |];
        [| 190; 74; 114; 163 |];
      |];
      [|
        [| 210; 68; 14; 170 |];
        [| 9; 104; 27; 97 |];
        [| 228; 196; 78; 234 |];
        [| 90; 142; 60; 73 |];
      |];
      [|
        [| 17; 227; 51; 182 |];
        [| 24; 139; 40; 215 |];
        [| 252; 79; 102; 61 |];
        [| 166; 193; 90; 116 |];
      |];
      [|
        [| 104; 174; 130; 52 |];
        [| 112; 37; 170; 227 |];
        [| 140; 106; 204; 222 |];
        [| 42; 171; 150; 170 |];
      |];
      [|
        [| 66; 176; 140; 197 |];
        [| 50; 149; 38; 38 |];
        [| 190; 255; 234; 248 |];
        [| 148; 84; 124; 82 |];
      |];
      [|
        [| 96; 80; 64; 98 |];
        [| 82; 197; 102; 68 |];
        [| 236; 58; 140; 188 |];
        [| 120; 110; 240; 238 |];
      |];
      [|
        [| 31; 12; 168; 60 |];
        [| 77; 201; 206; 120 |];
        [| 161; 243; 66; 196 |];
        [| 217; 157; 178; 42 |];
      |];
      [|
        [| 69; 44; 254; 46 |];
        [| 8; 229; 48; 86 |];
        [| 169; 22; 114; 146 |];
        [| 112; 139; 192; 184 |];
      |];
      [|
        [| 11; 140; 90; 103 |];
        [| 3; 105; 106; 49 |];
        [| 170; 127; 24; 163 |];
        [| 218; 244; 216; 27 |];
      |];
    |]
  in

  (* Validate the number of expanded keys *)
  assert_equal (Array.length expanded_keys) (Array.length expected_keys);

  (* Validate each round key *)
  Array.iteri
    (fun i round_key ->
      Printf.printf "Validating round key %d...\n" i;
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
  let message = "abcdefghabcdefghi" in

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

let tests =
  "test suite"
  >::: [
         "test_pad_block_1" >:: test_pad_block_1;
         "test_pad_block_2" >:: test_pad_block_2;
         "test_split_into_blocks_1" >:: test_split_into_blocks_1;
         "test_split_into_blocks_2" >:: test_split_into_blocks_2;
         "test_split_into_blocks_3" >:: test_split_into_blocks_3;
         "test_string_to_state_1" >:: test_string_to_state_1;
         "test_string_to_state_2" >:: test_string_to_state_2;
         "test_sub_bytes_1" >:: test_sub_bytes_1;
         "test_inv_sub_bytes_1" >:: test_inv_sub_bytes_1;
         "test_shift_rows_1" >:: test_shift_rows_1;
         "test_shift_rows_2" >:: test_shift_rows_2;
         "test_inv_shift_rows_1" >:: test_inv_shift_rows_1;
         "test_gmul_1" >:: test_gmul_1;
         "test_gmul_2" >:: test_gmul_2;
         "test_gmul_cases" >:: test_gmul_cases;
         "test_all_mix_columns_inverse" >:: test_all_mix_columns_inverse;
         "test_key_expansion" >:: test_key_expansion;
         "test_aes_encrypt_block" >:: test_aes_encrypt_block;
         "test_aes_decrypt_block" >:: test_aes_decrypt_block;
         "test_encrypt" >:: test_encrypt;
         (* "test_decrypt" >:: test_decrypt; *)
       ]

let _ = run_test_tt_main tests
