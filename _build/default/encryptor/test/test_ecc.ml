open OUnit2
include Encryptor.Ecc

(* Constants for ECC testing *)
let base_point = ECC.Point (3, 6)
let a = 2
let b = 3
let p = 97
let n = 5

(* Helper: Assert a point is valid on the curve *)
let assert_point_valid point =
  match point with
  | ECC.Point (x, y) ->
      assert_bool "Point must be on the curve"
        (ECC.is_on_curve (x, y) a b p)
  | Infinity -> ()

(* Test: Key generation produces valid keys *)
let ecc_key_generation_test1 _ =
  let keys = ECC.generate_keys base_point a b p n in
  assert_point_valid keys.public_key

(* Test: Multiple key generations produce distinct keys *)
let ecc_key_generation_test2 _ =
  let keys1 = ECC.generate_keys base_point a b p n in
  let keys2 = ECC.generate_keys base_point a b p n in
  assert_bool "Keys must be distinct" (keys1.public_key <> keys2.public_key)

(* Test: Scalar multiplication with small scalar *)
let ecc_scalar_mult_test1 _ =
  let scalar = 3 in
  let result = ECC.scalar_mult scalar base_point a p in
  assert_point_valid result

(* Test: Scalar multiplication with large scalar *)
let ecc_scalar_mult_test2 _ =
  let scalar = 50 in
  let result = ECC.scalar_mult scalar base_point a p in
  assert_point_valid result

(* Test: Scalar multiplication with scalar = 0 *)
let ecc_scalar_mult_zero_test _ =
  let scalar = 0 in
  let result = ECC.scalar_mult scalar base_point a p in
  assert_equal ECC.Infinity result

(* Test: Scalar multiplication for multiple random scalars *)
let ecc_scalar_mult_random_test _ =
  for _ = 1 to 10 do
    let scalar = Random.int 100 in
    let result = ECC.scalar_mult scalar base_point a p in
    assert_point_valid result
  done

(* Test: Point addition with distinct points *)
let ecc_point_addition_test1 _ =
  let point1 = base_point in
  let point2 = ECC.Point (80, 10) in
  let result = ECC.add point1 point2 a p in
  assert_point_valid result

(* Test: Point addition where one point is Infinity *)
let ecc_point_addition_infinity_test _ =
  let result = ECC.add base_point ECC.Infinity a p in
  assert_equal base_point result

(* Test: Point addition with the same point *)
let ecc_point_addition_self_test _ =
  let result = ECC.add base_point base_point a p in
  assert_point_valid result

(* Test: Point addition for multiple random points *)
let ecc_point_addition_random_test _ =
  for _ = 1 to 10 do
    let x1 = Random.int p in
    let y1 = Random.int p in
    let x2 = Random.int p in
    let y2 = Random.int p in
    if ECC.is_on_curve (x1, y1) a b p && ECC.is_on_curve (x2, y2) a b p then
      let point1 = ECC.Point (x1, y1) in
      let point2 = ECC.Point (x2, y2) in
      let result = ECC.add point1 point2 a p in
      assert_point_valid result
  done

(* Test: Encrypt and decrypt a small message *)
let ecc_encrypt_decrypt_test_small _ =
  let keys = ECC.generate_keys base_point a b p n in
  let message = 42 in
  let (c1, c2) = ECC.encrypt message base_point keys.public_key a b p n in
  let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
  assert_equal message decrypted_message

(* Test: Encrypt and decrypt a large message *)
let ecc_encrypt_decrypt_test_large _ =
  let keys = ECC.generate_keys base_point a b p n in
  let message = 89 in
  let (c1, c2) = ECC.encrypt message base_point keys.public_key a b p n in
  let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
  assert_equal message decrypted_message

(* Test: Encrypt and decrypt for multiple random messages *)
let ecc_encrypt_decrypt_random_test _ =
  for _ = 1 to 10 do
    let keys = ECC.generate_keys base_point a b p n in
    let message = Random.int (p - 1) in
    let (c1, c2) = ECC.encrypt message base_point keys.public_key a b p n in
    let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
    assert_equal message decrypted_message
  done

(* Test: Decrypt failure with incorrect private key *)
let ecc_decrypt_failure_wrong_key _ =
  let keys = ECC.generate_keys base_point a b p n in
  let wrong_keys = ECC.generate_keys base_point a b p n in
  let message = 50 in
  let (c1, c2) = ECC.encrypt message base_point keys.public_key a b p n in
  assert_raises (Failure "Decryption failed")
    (fun () -> ECC.decrypt (c1, c2) wrong_keys.private_key a p)

(* Test: Decrypt failure with tampered ciphertext *)
let ecc_decrypt_failure_tampered_cipher _ =
  let keys = ECC.generate_keys base_point a b p n in
  let message = 42 in
  let (c1, _) = ECC.encrypt message base_point keys.public_key a b p n in
  let tampered_c2 = ECC.Point (0, 0) in
  assert_raises (Failure "Decryption failed")
    (fun () -> ECC.decrypt (c1, tampered_c2) keys.private_key a p)

(* Test: Edge case messages for encryption and decryption *)
let ecc_encrypt_decrypt_edge_cases _ =
  let keys = ECC.generate_keys base_point a b p n in
  List.iter
    (fun msg ->
      let (c1, c2) = ECC.encrypt msg base_point keys.public_key a b p n in
      let decrypted_message = ECC.decrypt (c1, c2) keys.private_key a p in
      assert_equal msg decrypted_message)
    [0; 1; p - 1; 50; 97]


(* Group all ECC tests *)
let ecc_tests =
  [
    "ECC key generation test (valid keys)" >:: ecc_key_generation_test1;
    "ECC key generation test (distinct keys)" >:: ecc_key_generation_test2;
    "ECC scalar multiplication test (small scalar)" >:: ecc_scalar_mult_test1;
    "ECC scalar multiplication test (large scalar)" >:: ecc_scalar_mult_test2;
    "ECC scalar multiplication test (scalar = 0)"
    >:: ecc_scalar_mult_zero_test;
    "ECC scalar multiplication test (random scalars)"
    >:: ecc_scalar_mult_random_test;
    "ECC point addition test (distinct points)" >:: ecc_point_addition_test1;
    "ECC point addition test (with Infinity)"
    >:: ecc_point_addition_infinity_test;
    "ECC point addition test (same point)" >:: ecc_point_addition_self_test;
    "ECC point addition test (random points)"
    >:: ecc_point_addition_random_test;
    "ECC encrypt and decrypt test (small message)"
    >:: ecc_encrypt_decrypt_test_small;
    "ECC encrypt and decrypt test (large message)"
    >:: ecc_encrypt_decrypt_test_large;
    "ECC encrypt and decrypt test (random messages)"
    >:: ecc_encrypt_decrypt_random_test;
    "ECC decrypt failure test (wrong private key)"
    >:: ecc_decrypt_failure_wrong_key;
    "ECC decrypt failure test (tampered ciphertext)"
    >:: ecc_decrypt_failure_tampered_cipher;
    "ECC encrypt and decrypt edge cases" >:: ecc_encrypt_decrypt_edge_cases;
  ]

(* Run ECC tests *)
let () = run_test_tt_main ("ECC Test Suite" >::: ecc_tests)
