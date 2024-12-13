open OUnit2
include Encryptor.Ecc

(* Constants for ECC testing *)
let a, b, p, n = (2, 3, 97, 5)
let base_point = ECC.Point (3, 6)

(* Helper: Assert a point is valid on the curve *)
let assert_point_valid point =
  match point with
  | ECC.Point (x, y) ->
      assert_bool "Point must be on the curve" (ECC.is_on_curve (x, y) a b p)
  | Infinity -> ()

(* Key Generation Tests *)
let ecc_key_generation_valid_test _ =
  let keys = ECC.generate_keys base_point a b p n in
  assert_point_valid keys.public_key

(* Scalar Multiplication Tests *)
let ecc_scalar_mult_identity_test _ =
  let result = ECC.scalar_mult 1 base_point a p in
  assert_equal base_point result

let ecc_scalar_mult_zero_test _ =
  let result = ECC.scalar_mult 0 base_point a p in
  assert_equal ECC.Infinity result

let ecc_scalar_mult_small_test _ =
  let scalar = 2 in
  let result = ECC.scalar_mult scalar base_point a p in
  assert_point_valid result

let ecc_scalar_mult_large_test _ =
  let scalar = 50 in
  let result = ECC.scalar_mult scalar base_point a p in
  assert_point_valid result

(* Point Addition Tests *)
let ecc_point_addition_identity_test _ =
  let result = ECC.add base_point Infinity a p in
  assert_equal base_point result

let ecc_point_addition_inverse_test _ =
  let point1 = base_point in
  let point2 = ECC.Point (3, -6 mod p) in
  let result = ECC.add point1 point2 a p in
  assert_equal ECC.Infinity result

let ecc_point_addition_same_point_test _ =
  let result = ECC.add base_point base_point a p in
  assert_point_valid result

let ecc_point_addition_commutative_test _ =
  let point1 = ECC.scalar_mult 3 base_point a p in
  let point2 = ECC.scalar_mult 2 base_point a p in
  let result1 = ECC.add point1 point2 a p in
  let result2 = ECC.add point2 point1 a p in
  assert_equal result1 result2

let ecc_point_addition_associative_test _ =
  let point1 = ECC.scalar_mult 3 base_point a p in
  let point2 = ECC.scalar_mult 2 base_point a p in
  let point3 = ECC.scalar_mult 1 base_point a p in
  let result1 = ECC.add point1 (ECC.add point2 point3 a p) a p in
  let result2 = ECC.add (ECC.add point1 point2 a p) point3 a p in
  assert_equal result1 result2

(* Encryption and Decryption Tests *)
let ecc_encrypt_decrypt_small_test _ =
  let keys = ECC.generate_keys base_point a b p n in
  let message = 42 in
  let c1, c2 = ECC.encrypt message base_point keys.public_key a b p n in
  let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
  assert_equal message decrypted_message

let ecc_encrypt_decrypt_edge_cases_test _ =
  let keys = ECC.generate_keys base_point a b p n in
  List.iter
    (fun msg ->
      let c1, c2 = ECC.encrypt msg base_point keys.public_key a b p n in
      let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
      assert_equal msg decrypted_message)
    [ 0; 1; p - 1 ]

(* Boundary Value Tests *)
let ecc_scalar_mult_boundary_test _ =
  List.iter
    (fun scalar ->
      let result = ECC.scalar_mult scalar base_point a p in
      assert_point_valid result)
    [ 1; 2; p - 1 ]

let ecc_point_addition_boundary_test _ =
  let point1 = ECC.Point (3, 6) in
  let point2 = ECC.Point (3, 6) in
  let result = ECC.add point1 point2 a p in
  assert_point_valid result

(* Group all ECC tests *)
let ecc_tests =
  [
    (* Key Generation Tests *)
    "ECC key generation valid" >:: ecc_key_generation_valid_test;
    (* Scalar Multiplication Tests *)
    "ECC scalar multiplication identity" >:: ecc_scalar_mult_identity_test;
    "ECC scalar multiplication zero" >:: ecc_scalar_mult_zero_test;
    "ECC scalar multiplication small" >:: ecc_scalar_mult_small_test;
    "ECC scalar multiplication large" >:: ecc_scalar_mult_large_test;
    (* Point Addition Tests *)
    "ECC point addition identity" >:: ecc_point_addition_identity_test;
    "ECC point addition inverse" >:: ecc_point_addition_inverse_test;
    "ECC point addition same point" >:: ecc_point_addition_same_point_test;
    "ECC point addition commutative" >:: ecc_point_addition_commutative_test;
    "ECC point addition associative" >:: ecc_point_addition_associative_test;
    (* Encryption and Decryption Tests *)
    "ECC encrypt and decrypt small" >:: ecc_encrypt_decrypt_small_test;
    "ECC encrypt and decrypt edge cases" >:: ecc_encrypt_decrypt_edge_cases_test;
    (* Boundary Value Tests *)
    "ECC scalar multiplication boundary" >:: ecc_scalar_mult_boundary_test;
    "ECC point addition boundary" >:: ecc_point_addition_boundary_test;
  ]

(* Run ECC tests *)
let () = run_test_tt_main ("ECC Test Suite" >::: ecc_tests)
