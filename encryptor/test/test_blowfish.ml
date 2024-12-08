open OUnit2
open Encryptor.Blowfish

let conversion_test1 _ =
  let num = binary_to_int (int_to_binary 12345678) in
  assert_equal num 12345678

let conversion_test2 _ =
  let num = binary_to_int (int_to_binary 238928) in
  assert_equal num 238928

let conversion_test3 _ =
  let num = binary_to_int (int_to_binary 238291823) in
  assert_equal num 238291823

let conversion_test4 _ =
  let num = binary_to_int (int_to_binary 111111) in
  assert_equal num 111111

let sub_test1 _ =
  let lst =
    [ 1; 0; 0; 1; 0; 1; 0; 1; 1; 0; 1; 0; 1; 0; 0; 1; 1; 1; 1; 0; 1; 0; 0; 1 ]
  in
  let sub_lst = sub 3 7 lst in
  assert_equal sub_lst [ 1; 0; 1; 0 ]

let sub_test2 _ =
  let lst =
    [ 1; 0; 0; 1; 0; 1; 0; 1; 1; 0; 1; 0; 1; 0; 0; 1; 1; 1; 1; 0; 1; 0; 0; 1 ]
  in
  let sub_lst = sub 8 10 lst in
  assert_equal sub_lst [ 1; 0 ]

let xor_test1 _ =
  let bin1 = int_to_binary 12345678 in
  let bin2 = int_to_binary 608135816 in
  let result = binary_to_int (xor bin1 bin2) in
  assert_equal result 612568006

let xor_test2 _ =
  let bin1 = int_to_binary 422970021 in
  let bin2 = int_to_binary 3941167025 in
  let result = binary_to_int (xor bin1 bin2) in
  assert_equal result 4091505940

let binary_string_conversion_test1 _ =
  let str = "abcaa" in
  let bin = string_to_binary str in
  let converted = binary_to_string bin in
  assert_equal converted str

let binary_string_conversion_test2 _ =
  let str = "ab aak!h" in
  let bin = string_to_binary str in
  let converted = binary_to_string bin in
  assert_equal converted str

let binary_string_conversion_test3 _ =
  let str = "kj    $ " in
  let bin = string_to_binary str in
  let converted = binary_to_string bin in
  assert_equal converted str

let encrypt_decrypt_test1 _ =
  let key = 12345678 in
  let message = "I love  " in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

let encrypt_decrypt_test2 _ =
  let key = 27778902 in
  let message = "cow . ho" in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

let encrypt_decrypt_test3 _ =
  let key = 00000000 in
  let message = "init" in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

let encrypt_decrypt_test4 _ =
  let key = 12345678 in
  let message = "hi & )" in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

let binary_str_to_lst_test1 _ =
  let binary_str = "0110100" in
  let bin_lst = binary_string_to_list binary_str in
  assert_equal bin_lst [ 0; 1; 1; 0; 1; 0; 0 ]

let tests =
  "test suite"
  >::: [
         "Conversion function test:" >:: conversion_test1;
         "Conversion function test:" >:: conversion_test2;
         "Conversion function test:" >:: conversion_test3;
         "Conversion function test:" >:: conversion_test4;
         "Sub-list function test: " >:: sub_test1;
         "Sub-list function test: " >:: sub_test2;
         "Xor test: " >:: xor_test1;
         "Xor test: " >:: xor_test2;
         "Binary and string conversion test:" >:: binary_string_conversion_test1;
         "Binary and string conversion test:" >:: binary_string_conversion_test2;
         "Binary and string conversion test:" >:: binary_string_conversion_test3;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test1;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test2;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test3;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test4;
         "Binary string to list test: " >:: binary_str_to_lst_test1;
       ]

let _ = run_test_tt_main tests
