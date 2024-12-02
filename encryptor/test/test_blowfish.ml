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
       ]

let _ = run_test_tt_main tests
