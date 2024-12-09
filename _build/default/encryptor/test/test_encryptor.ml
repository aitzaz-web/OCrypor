open OUnit2
open Encryptor.Rsa
open Encryptor.Util

(** [string_to_ascii_list] converts a string to a list of ASCII values. *)
let string_to_ascii_list word =
  let chars = List.of_seq (String.to_seq word) in
  chars |> List.map Char.code

(** [ascii_list_to_string] converts a list of ASCII values back to a string. *)
let ascii_list_to_string ascii_list =
  String.init (List.length ascii_list) (fun i ->
      Char.chr (List.nth ascii_list i))


(**[pow b e] calculates a base [b] to the power [e].*)
let rec pow b e = if e = 0 then 1 else b * pow b (e - 1)

(********************************* util.ml tests *****************************)

(**[is_prime_test1] tests that a prime number is prime.*)
let is_prime_test1 _ = assert_equal (is_prime 59) true

(**[is_prime_test2] tests that a non-prime number is non-prime.*)
let is_prime_test2 _ = assert_equal (is_prime 9) false

(**[is_prime_test3] tests that a prime number is prime.*)
let is_prime_test3 _ = assert_equal (is_prime 227) true

(**[is_prime_test4] tests that a non-prime number is non-prime.*)
let is_prime_test4 _ = assert_equal (is_prime 1002) false

(**[is_prime_test5] tests that a prime number is prime.*)
let is_prime_test5 _ = assert_equal (is_prime 1009) true

(**[generate_prime_test1] tests that generating a random prime number \
   [generate_prime min max] produces a number that is prime and in the \ range
   of [min, max].*)
let generate_prime_test1 _ =
  let random_num = generate_prime 11 32 in
  assert_equal (is_prime random_num) true;
  assert_equal true (random_num >= 11 && random_num <= 32)

(**[generate_prime_test2] tests that generating a random prime number \
   [generate_prime min max] produces a number that is prime and in the \ range
   of [min, max].*)
let generate_prime_test2 _ =
  let random_num = generate_prime 200 1000 in
  assert_equal (is_prime random_num) true;
  assert_equal true (random_num >= 200 && random_num <= 1000)

(**[generate_prime_test3] tests that generating a random prime number \
   [generate_prime min max] produces a number that is prime and in the \ range
   of [min, max].*)
let generate_prime_test3 _ =
  let random_num = generate_prime 1002 1500 in
  assert_equal (is_prime random_num) true;
  assert_equal true (random_num >= 1002 && random_num <= 1500)

(**[generate_prime_test4] tests that generating a random prime number \
   [generate_prime min max] produces a number that is prime and in the \ range
   of [min, max].*)
let generate_prime_test4 _ =
  let random_num = generate_prime 1400 2000 in
  assert_equal (is_prime random_num) true;
  assert_equal true (random_num >= 1400 && random_num <= 2000)

(**[generate_prime_test5] tests that generating a random prime number \
   [generate_prime min max] produces a number that is prime and in the \ range
   of [min, max].*)
let generate_prime_test5 _ =
  let random_num = generate_prime 3212 323242 in
  assert_equal (is_prime random_num) true;
  assert_equal true (random_num >= 3212 && random_num <= 323242)

(**[find_gcd_test1] tests for the gcd between two numbers when the gcd is non-1.*)
let find_gcd_test1 _ = assert_equal 4 (find_gcd 8 12)

(**[find_gcd_test2] tests for the gcd between two numbers when the gcd is 1.*)
let find_gcd_test2 _ = assert_equal 1 (find_gcd 17 31)

(**[find_gcd_test3] tests for the gcd between two numbers when the gcd is non-1.*)
let find_gcd_test3 _ = assert_equal 11 (find_gcd 44 121)

(**[find_gcd_test4] tests for the gcd between two numbers when the gcd is 1.*)
let find_gcd_test4 _ = assert_equal 1 (find_gcd 23 57)

(**[find_gcd_test5] tests for the gcd between two numbers when the gcd is non-1.*)
let find_gcd_test5 _ = assert_equal 120 (find_gcd 360 840)

(** [gcd_ext_test1] tests the extended GCD for (12, 0). *)
let gcd_ext_test1 _ = assert_equal (1, 0, 12) (gcd_ext 12 0)

(** [gcd_ext_test2] tests the extended GCD for (7, 3). *)
let gcd_ext_test2 _ = assert_equal (1, -2, 1) (gcd_ext 7 3)

(** [gcd_ext_test3] tests the extended GCD for (58, 348). *)
let gcd_ext_test3 _ = assert_equal (1, 0, 58) (gcd_ext 58 348)

(** [gcd_ext_test4] tests the extended GCD for (55, 80). *)
let gcd_ext_test4 _ = assert_equal (3, -2, 5) (gcd_ext 55 80)

(** [gcd_ext_test5] tests the extended GCD for (252, 198). *)
let gcd_ext_test5 _ = assert_equal (4, -5, 18) (gcd_ext 252 198)

(** [mod_inv_test1] tests the modular inverse of two coprime numbers.*)
let mod_inv_test1 _ = assert_equal 1 (mod_inv 3 2)

(** [mod_inv_test2] tests the modular inverse of two more coprime numbers.*)
let mod_inv_test2 _ = assert_equal 7 (mod_inv 3 10)

(** [mod_inv_test3] tests that mod_inv raises a failure when the modular inverse
    cannot exist.*)
let mod_inv_test3 _ = assert_raises (Failure "mod_inv") (fun () -> mod_inv 2 4)

(********************************* rsa.ml tests *****************************)

(** [mod_exp_test1] tests modular exponentiation when the exponent is 0. *)
let mod_exp_test1 _ = assert_equal 1 (Rsa.mod_exp 5 0 13)

(** [mod_exp_test2] tests modular exponentiation for an odd exponent. *)
let mod_exp_test2 _ = assert_equal 8 (Rsa.mod_exp 5 3 13)

(** [mod_exp_test3] tests modular exponentiation for an even exponent. *)
let mod_exp_test3 _ = assert_equal 1 (Rsa.mod_exp 4 2 3)

(** [rsa_encrypt_test1] tests RSA encryption. *)
let rsa_encrypt_test1 _ = assert_equal 4 (Rsa.rsa_encrypt 3 (2, 5))

(** [rsa_encrypt_test2] tests RSA encryption. *)
let rsa_encrypt_test2 _ = assert_equal 1 (Rsa.rsa_encrypt 26 (2, 5))

(** [rsa_encrypt_test3] tests RSA encryption. *)
let rsa_encrypt_test3 _ =
  let message = string_to_ascii_list "words" in
  let encrypted = List.map (fun x -> Rsa.rsa_encrypt x (5, 14)) message in
  for x = 0 to List.length message - 1 do
    let n = List.nth message x in
    assert_equal (pow n 5 mod 14) (List.nth encrypted x)
  done

(** [rsa_encrypt_test4] tests RSA encryption. *)
let rsa_encrypt_test4 _ =
  let message = string_to_ascii_list "pizza" in
  let encrypted = List.map (fun x -> Rsa.rsa_encrypt x (4, 34)) message in
  for x = 0 to List.length message - 1 do
    let n = List.nth message x in
    assert_equal (pow n 4 mod 34) (List.nth encrypted x)
  done

(** [rsa_encrypt_test5] tests RSA encryption. *)
let rsa_encrypt_test5 _ =
  let message = string_to_ascii_list "steak and eggs" in
  let encrypted = List.map (fun x -> Rsa.rsa_encrypt x (8, 44)) message in
  for x = 0 to List.length message - 1 do
    let n = List.nth message x in
    assert_equal (pow n 8 mod 44) (List.nth encrypted x)
  done

(** [rsa_decrypt_test1] tests RSA decryption. *)
let rsa_decrypt_test1 _ = assert_equal 8 (Rsa.rsa_decrypt 8 (11, 14))

(** [rsa_encrypt_decrypt_test_num1] tests that decryption correctly recovers the
    original int message after encryption. *)
let rsa_encrypt_decrypt_test_num1 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = 42 in
  let encrypted = Rsa.rsa_encrypt message (e, x) in
  let decrypted = Rsa.rsa_decrypt encrypted (d, y) in
  assert_equal message decrypted

(** [rsa_encrypt_decrypt_test_num2] tests that decryption correctly recovers the
    original int message after encryption. *)
let rsa_encrypt_decrypt_test_num2 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = 23728 in
  let encrypted = Rsa.rsa_encrypt message (e, x) in
  let decrypted = Rsa.rsa_decrypt encrypted (d, y) in
  assert_equal message decrypted

(** [rsa_encrypt_decrypt_test_num3] tests that decryption correctly recovers the
    original int message after encryption. *)
let rsa_encrypt_decrypt_test_num3 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = 821323 in
  let encrypted = Rsa.rsa_encrypt message (e, x) in
  let decrypted = Rsa.rsa_decrypt encrypted (d, y) in
  assert_equal message decrypted

(** [rsa_encrypt_decrypt_test_num4] tests that decryption correctly recovers the
    original int message after encryption. *)
let rsa_encrypt_decrypt_test_num4 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = 2138213 in
  let encrypted = Rsa.rsa_encrypt message (e, x) in
  let decrypted = Rsa.rsa_decrypt encrypted (d, y) in
  assert_equal message decrypted

(** [rsa_encrypt_decrypt_test_num5] tests that decryption correctly recovers the
    original int message after encryption. *)
let rsa_encrypt_decrypt_test_num5 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = 888999 in
  let encrypted = Rsa.rsa_encrypt message (e, x) in
  let decrypted = Rsa.rsa_decrypt encrypted (d, y) in
  assert_equal message decrypted

(**[rsa_encrypt_decrypt_test_string1] tests that decryption correctly recovers
   the original string message after encryption. *)
let rsa_encrypt_decrypt_test_string1 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = "secret" in
  let ascii_message = string_to_ascii_list message in
  let encrypted = List.map (fun c -> Rsa.rsa_encrypt c (e, x)) ascii_message in
  let decrypted = List.map (fun c -> Rsa.rsa_decrypt c (d, y)) encrypted in
  let decrypted_message = ascii_list_to_string decrypted in
  assert_equal message decrypted_message

(**[rsa_encrypt_decrypt_test_string2] tests that decryption correctly recovers
   the original string message after encryption. *)
let rsa_encrypt_decrypt_test_string2 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = "Functional programming. Object-oriented programming." in
  let ascii_message = string_to_ascii_list message in
  let encrypted = List.map (fun c -> Rsa.rsa_encrypt c (e, x)) ascii_message in
  let decrypted = List.map (fun c -> Rsa.rsa_decrypt c (d, y)) encrypted in
  let decrypted_message = ascii_list_to_string decrypted in
  assert_equal message decrypted_message

(**[rsa_encrypt_decrypt_test_string3] tests that decryption correctly recovers
   the original string message after encryption. *)
let rsa_encrypt_decrypt_test_string3 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = "" in
  let ascii_message = string_to_ascii_list message in
  let encrypted = List.map (fun c -> Rsa.rsa_encrypt c (e, x)) ascii_message in
  let decrypted = List.map (fun c -> Rsa.rsa_decrypt c (d, y)) encrypted in
  let decrypted_message = ascii_list_to_string decrypted in
  assert_equal message decrypted_message

(**[rsa_encrypt_decrypt_test_string4] tests that decryption correctly recovers
   the original string message after encryption. *)
let rsa_encrypt_decrypt_test_string4 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = "Cornell's CS 3110 class is held in Baker." in
  let ascii_message = string_to_ascii_list message in
  let encrypted = List.map (fun c -> Rsa.rsa_encrypt c (e, x)) ascii_message in
  let decrypted = List.map (fun c -> Rsa.rsa_decrypt c (d, y)) encrypted in
  let decrypted_message = ascii_list_to_string decrypted in
  assert_equal message decrypted_message

(**[rsa_encrypt_decrypt_test_string5] tests that decryption correctly recovers
   the original string message after encryption. *)
let rsa_encrypt_decrypt_test_string5 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = "//! word.-+ ." in
  let ascii_message = string_to_ascii_list message in
  let encrypted = List.map (fun c -> Rsa.rsa_encrypt c (e, x)) ascii_message in
  let decrypted = List.map (fun c -> Rsa.rsa_decrypt c (d, y)) encrypted in
  let decrypted_message = ascii_list_to_string decrypted in
  assert_equal message decrypted_message

(** [generate_keys_test1] tests that generated keys are valid RSA keys. *)
let generate_keys_test1 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  assert_equal true (e > 0 && x > 0);
  assert_equal true (d > 0 && y > 0)

(** [generate_keys_test2] tests that generated keys are valid RSA keys. *)
let generate_keys_test2 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  assert_equal true (e > 0 && x > 0);
  assert_equal true (d > 0 && y > 0)

(** [generate_keys_test3] tests that generated keys are valid RSA keys. *)
let generate_keys_test3 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  assert_equal true (e > 0 && x > 0);
  assert_equal true (d > 0 && y > 0)

let tests =
  "test suite"
  >::: [
         "is_prime test: " >:: is_prime_test1;
         "is_prime test: " >:: is_prime_test2;
         "is_prime test: " >:: is_prime_test3;
         "is_prime test: " >:: is_prime_test4;
         "is_prime test: " >:: is_prime_test5;
         "generate_prime test: " >:: generate_prime_test1;
         "generate_prime test: " >:: generate_prime_test2;
         "generate_prime test: " >:: generate_prime_test3;
         "generate_prime test: " >:: generate_prime_test4;
         "generate_prime test: " >:: generate_prime_test5;
         "find_gcd test: " >:: find_gcd_test1;
         "find_gcd test: " >:: find_gcd_test2;
         "find_gcd test: " >:: find_gcd_test3;
         "find_gcd test: " >:: find_gcd_test4;
         "find_gcd test: " >:: find_gcd_test5;
         "gcd_ext test: " >:: gcd_ext_test1;
         "gcd_ext test: " >:: gcd_ext_test2;
         "gcd_ext test: " >:: gcd_ext_test3;
         "gcd_ext test: " >:: gcd_ext_test4;
         "gcd_ext test: " >:: gcd_ext_test5;
         "mod_inv test: " >:: mod_inv_test1;
         "mod_inv test: " >:: mod_inv_test2;
         "mod_inv test: " >:: mod_inv_test3;
         "mod_exp test: " >:: mod_exp_test1;
         "mod_exp test: " >:: mod_exp_test2;
         "mod_exp test: " >:: mod_exp_test3;
         "rsa_encrypt test: " >:: rsa_encrypt_test1;
         "rsa_encrypt test: " >:: rsa_encrypt_test2;
         "rsa_encrypt test: " >:: rsa_encrypt_test3;
         "rsa_encrypt test: " >:: rsa_encrypt_test4;
         "rsa_encrypt test: " >:: rsa_encrypt_test5;
         "rsa_decrypt test: " >:: rsa_decrypt_test1;
         "rsa_encrypt and rsa_decrypt test: " >:: rsa_encrypt_decrypt_test_num1;
         "rsa_encrypt and rsa_decrypt test: " >:: rsa_encrypt_decrypt_test_num2;
         "rsa_encrypt and rsa_decrypt test: " >:: rsa_encrypt_decrypt_test_num3;
         "rsa_encrypt and rsa_decrypt test: " >:: rsa_encrypt_decrypt_test_num4;
         "rsa_encrypt and rsa_decrypt test: " >:: rsa_encrypt_decrypt_test_num5;
         "rsa_encrypt and rsa_decrypt test: "
         >:: rsa_encrypt_decrypt_test_string1;
         "rsa_encrypt and rsa_decrypt test: "
         >:: rsa_encrypt_decrypt_test_string2;
         "rsa_encrypt and rsa_decrypt test: "
         >:: rsa_encrypt_decrypt_test_string3;
         "rsa_encrypt and rsa_decrypt test: "
         >:: rsa_encrypt_decrypt_test_string4;
         "rsa_encrypt and rsa_decrypt test: "
         >:: rsa_encrypt_decrypt_test_string5;
         "generate_keys test: " >:: generate_keys_test1;
         "generate_keys test: " >:: generate_keys_test2;
         "generate_keys test: " >:: generate_keys_test3;
       ]
  

let _ = run_test_tt_main tests
