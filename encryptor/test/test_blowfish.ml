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


let tests =
  "test suite"
  >::: [
         "Conversion function test:" >:: conversion_test1;
         "Conversion function test:" >:: conversion_test2;
         "Conversion function test:" >:: conversion_test3;
         "Conversion function test:" >:: conversion_test4;
       ]

let _ = run_test_tt_main tests
