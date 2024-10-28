open OUnit2
open Encryptor.Rsa
open Encryptor.Util

(********************************* util.ml tests *****************************)

(**[is_prime_test1] tests that a prime number is prime.*)
let is_prime_test1 _ = assert_equal (is_prime 59) true

(**[is_prime_test2] tests that a non-prime number is non-prime.*)
let is_prime_test2 _ = assert_equal (is_prime 9) false

(**[generate_prime_test1] tests that generating a random prime number \
   [generate_prime min max] produces a number that is prime and in the \ range
   of [min, max].*)
let generate_prime_test1 _ =
  let random_num = generate_prime 11 32 in
  assert_equal (is_prime random_num) true;
  assert_equal true (random_num >= 11 && random_num <= 32)

(**[find_gcd_test1] tests for the gcd between two numbers when the gcd is non-1.*)
let find_gcd_test1 _ = assert_equal 4 (find_gcd 8 12)

(**[find_gcd_test2] tests for the gcd between two numbers when the gcd is 1.*)
let find_gcd_test2 _ = assert_equal 1 (find_gcd 17 31)

(** [gcd_ext_test1] tests the extended GCD for (12, 0). *)
let gcd_ext_test1 _ = assert_equal (1, 0, 12) (gcd_ext 12 0)

(** [gcd_ext_test2] tests the extended GCD for (7, 3). *)
let gcd_ext_test2 _ = assert_equal (1, -2, 1) (gcd_ext 7 3)

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

(** [rsa_decrypt_test1] tests RSA decryption. *)
let rsa_decrypt_test1 _ = assert_equal 8 (Rsa.rsa_decrypt 8 (11, 14))

(** [rsa_encrypt_decrypt_test] tests that decryption correctly recovers the
    original message. *)
let rsa_encrypt_decrypt_test _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  let message = 42 in
  let encrypted = Rsa.rsa_encrypt message (e, x) in
  let decrypted = Rsa.rsa_decrypt encrypted (d, y) in
  assert_equal message decrypted

(** [generate_keys_test] tests that generated keys are valid RSA keys. *)
let generate_keys_test1 _ =
  let (e, x), (d, y) = Rsa.generate_keys () in
  assert_equal true (e > 0 && x > 0);
  assert_equal true (d > 0 && y > 0)

let tests =
  "test suite"
  >::: [
         "is_prime test: " >:: is_prime_test1;
         "is_prime test: " >:: is_prime_test2;
         "generate_prime test: " >:: generate_prime_test1;
         "find_gcd test: " >:: find_gcd_test1;
         "find_gcd test: " >:: find_gcd_test2;
         "gcd_ext test: " >:: gcd_ext_test1;
         "gcd_ext test: " >:: gcd_ext_test2;
         "mod_inv test: " >:: mod_inv_test1;
         "mod_inv test: " >:: mod_inv_test2;
         "mod_inv test: " >:: mod_inv_test3;
         "mod_exp test: " >:: mod_exp_test1;
         "mod_exp test: " >:: mod_exp_test2;
         "mod_exp test: " >:: mod_exp_test3;
         "rsa_encrypt test: " >:: rsa_encrypt_test1;
         "rsa_decrypt test: " >:: rsa_decrypt_test1;
         "rsa_encrypt and rsa_decrypt test: " >:: rsa_encrypt_decrypt_test;
         "generate_keys test: " >:: generate_keys_test1;
       ]

let _ = run_test_tt_main tests
