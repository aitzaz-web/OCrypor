open OUnit2
open Encryptor.Rsa
open Encryptor.Util
open Encryptor.Sha3

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

(********************************* RC2 component tests
  *****************************)

(** [read_int64_file_test1] tests reading Int64 hex values from a file *)
let read_int64_file_test1 _ =
  (* Create a temporary file with test data *)
  let filename = "test_hex.txt" in
  let test_values = [ "1A"; "2B"; "3C" ] in
  let oc = open_out filename in
  List.iter (fun v -> Printf.fprintf oc "%s\n" v) test_values;
  close_out oc;
  let result = read_int64_file filename in
  Sys.remove filename;
  assert_equal 3 (Array.length result);
  assert_equal (Int64.of_int 0x1A) result.(0);
  assert_equal (Int64.of_int 0x2B) result.(1);
  assert_equal (Int64.of_int 0x3C) result.(2)

(** [rotl64_test1] tests basic left rotation by 1 bit *)
let rotl64_test1 _ =
  let input = Int64.of_int 1 in
  let expected = Int64.shift_left (Int64.of_int 1) 1 in
  assert_equal expected (rotl64 input 1)

(** [rotl64_test2] tests rotation that wraps around *)
let rotl64_test2 _ =
  let input = Int64.shift_left Int64.one 63 in
  let expected = Int64.one in
  assert_equal expected (rotl64 input 1)

(** [rotl64_test3] tests rotation by 0 bits (no change) *)
let rotl64_test3 _ =
  let input = Int64.of_int 0xABCD in
  assert_equal input (rotl64 input 0)

(** [to_state_test1] tests creation of empty 5x5 matrix *)
let to_state_test1 _ =
  let state = to_state [||] in
  assert_equal 5 (Array.length state);
  assert_equal 5 (Array.length state.(0));
  for i = 0 to 4 do
    for j = 0 to 4 do
      assert_equal Int64.zero state.(i).(j)
    done
  done

(** [to_state_test2] tests initialization remains consistent *)
let to_state_test2 _ =
  let state1 = to_state [||] in
  let state2 = to_state [||] in
  for i = 0 to 4 do
    for j = 0 to 4 do
      assert_equal state1.(i).(j) state2.(i).(j)
    done
  done

(** [from_state_test1] tests conversion from 5x5 matrix to linear array *)
let from_state_test1 _ =
  let state = Array.make_matrix 5 5 0L in
  (* Set some test values *)
  state.(0).(0) <- Int64.of_int 1;
  state.(1).(1) <- Int64.of_int 2;
  state.(2).(2) <- Int64.of_int 3;
  state.(3).(3) <- Int64.of_int 4;
  state.(4).(4) <- Int64.of_int 5;

  let result = from_state state in
  assert_equal 25 (Array.length result);
  assert_equal (Int64.of_int 1) result.(0);
  assert_equal (Int64.of_int 2) result.(6);
  assert_equal (Int64.of_int 3) result.(12);
  assert_equal (Int64.of_int 4) result.(18);
  assert_equal (Int64.of_int 5) result.(24)

(** [from_state_test2] tests tffhat all zeros are preserved *)
let from_state_test2 _ =
  let state = Array.make_matrix 5 5 0L in
  let result = from_state state in
  assert_equal 25 (Array.length result);
  Array.iter (fun x -> assert_equal Int64.zero x) result

open OUnit2

(* Helper function to create a 5x5 state array from a list of lists *)
let create_state_from_list lst = Array.of_list (List.map Array.of_list lst)

(* Test data - a simple 5x5 state matrix *)
let test_state =
  create_state_from_list
    [
      [ 1L; 2L; 3L; 4L; 5L ];
      [ 6L; 7L; 8L; 9L; 10L ];
      [ 11L; 12L; 13L; 14L; 15L ];
      [ 16L; 17L; 18L; 19L; 20L ];
      [ 21L; 22L; 23L; 24L; 25L ];
    ]

let test_xor_slice_simple _ =
  let arr =
    [|
      Int64.of_int 1;
      Int64.of_int 2;
      Int64.of_int 3;
      Int64.of_int 4;
      Int64.of_int 5;
    |]
  in
  assert_equal
    Int64.(of_int 0)
    (Encryptor.Sha3.xor_slice arr 0 2)
    ~printer:Int64.to_string;
  assert_equal
    Int64.(of_int 4)
    (Encryptor.Sha3.xor_slice arr 0 3)
    ~printer:Int64.to_string

let test_compute_column_parity _ =
  let test_state =
    Array.init 5 (fun i ->
        Array.init 5 (fun j -> Int64.of_int ((i + 1) * (j + 1))))
  in

  let result = Encryptor.Sha3.compute_column_parity test_state in

  let expected =
    [|
      Int64.of_int (1 lxor 2 lxor 3 lxor 4 lxor 5);
      (* First column *)
      Int64.of_int (2 lxor 4 lxor 6 lxor 8 lxor 10);
      (* Second column *)
      Int64.of_int (3 lxor 6 lxor 9 lxor 12 lxor 15);
      (* Third column *)
      Int64.of_int (4 lxor 8 lxor 12 lxor 16 lxor 20);
      (* Fourth column *)
      Int64.of_int (5 lxor 10 lxor 15 lxor 20 lxor 25)
      (* Fifth column *);
    |]
  in

  (* Check that the result array has the correct length *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;

  (* Check each column's parity matches expected value *)
  Array.iteri
    (fun i x ->
      assert_equal
        ~msg:(Printf.sprintf "Column %d parity mismatch" i)
        ~printer:Int64.to_string expected.(i) x)
    result

let test_compute_theta_d _ =
  let c = Array.map Int64.of_int [| 1; 2; 4; 8; 16 |] in

  let result = Encryptor.Sha3.compute_theta_d c in

  let expected_at_x x =
    let x4 = c.((x + 4) mod 5) in
    (* Value from x+4 position *)
    let x1_rotated = rotl64 c.((x + 1) mod 5) 1 in
    (* Rotated value from x+1 position *)
    Int64.logxor x4 x1_rotated
  in

  assert_equal 5 (Array.length result) ~printer:string_of_int;

  (* For x = 0: - Uses c[4] (16) and rotated c[1] (2 rotated left by 1 = 4)
     Expected: 16 XOR 4 *)
  assert_equal ~msg:"Failed at x=0" ~printer:Int64.to_string (expected_at_x 0)
    result.(0);

  (* For x = 1: - Uses c[0] (1) and rotated c[2] (4 rotated left by 1 = 8)
     Expected: 1 XOR 8 *)
  assert_equal ~msg:"Failed at x=1" ~printer:Int64.to_string (expected_at_x 1)
    result.(1);

  (* For x = 2: - Uses c[1] (2) and rotated c[3] (8 rotated left by 1 = 16)
     Expected: 2 XOR 16 *)
  assert_equal ~msg:"Failed at x=2" ~printer:Int64.to_string (expected_at_x 2)
    result.(2);

  (* For x = 3: - Uses c[2] (4) and rotated c[4] (16 rotated left by 1 = 32)
     Expected: 4 XOR 32 *)
  assert_equal ~msg:"Failed at x=3" ~printer:Int64.to_string (expected_at_x 3)
    result.(3);

  (* For x = 4: - Uses c[3] (8) and rotated c[0] (1 rotated left by 1 = 2)
     Expected: 8 XOR 2 *)
  assert_equal ~msg:"Failed at x=4" ~printer:Int64.to_string (expected_at_x 4)
    result.(4)

let create_test_state () =
  Array.init 5 (fun x ->
      Array.init 5 (fun y -> Int64.of_int ((x + 1) * (y + 1))))

let test_theta _ =
  let state = create_test_state () in
  let result = Encryptor.Sha3.theta state in

  (* Test dimensions *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;
  assert_equal 5 (Array.length result.(0)) ~printer:string_of_int;

  (* Verify that result is a new array *)
  assert_bool "Should create new array" (result != state);

  (* Compute expected values manually *)
  let c = Encryptor.Sha3.compute_column_parity state in
  let d = Encryptor.Sha3.compute_theta_d c in

  (* Check that each position is correctly transformed *)
  for x = 0 to 4 do
    for y = 0 to 4 do
      let expected = Int64.logxor state.(x).(y) d.(x) in
      assert_equal
        ~msg:(Printf.sprintf "Mismatch at position (%d,%d)" x y)
        ~printer:Int64.to_string expected
        result.(x).(y)
    done
  done

let test_compute_rho_offset _ =
  (* Test first few values *)
  let test_cases =
    [
      (0, 1);
      (* (0+1)*(0+2)/2 = 1 *)
      (1, 3);
      (* (1+1)*(1+2)/2 = 3 *)
      (2, 6);
      (* (2+1)*(2+2)/2 = 6 *)
      (3, 10);
      (* (3+1)*(3+2)/2 = 10 *)
      (4, 15);
      (* (4+1)*(4+2)/2 = 15 *)
      (5, 21);
      (* (5+1)*(5+2)/2 = 21 *)
    ]
  in

  List.iter
    (fun (input, expected) ->
      assert_equal
        ~msg:(Printf.sprintf "Rho offset mismatch for t=%d" input)
        ~printer:string_of_int expected
        (Encryptor.Sha3.compute_rho_offset input))
    test_cases;

  (* Test that results are always within valid range (0-63) *)
  for t = 0 to 23 do
    let result = Encryptor.Sha3.compute_rho_offset t in
    assert_bool
      (Printf.sprintf "Offset %d out of range for t=%d" result t)
      (result >= 0 && result < 64)
  done

let test_compute_pi_position _ =
  (* Test known mappings *)
  let test_cases =
    [
      ((0, 0), (0, 0));
      (* y=0, (2*0 + 3*0) mod 5 = 0 *)
      ((1, 0), (0, 2));
      (* y=0, (2*1 + 3*0) mod 5 = 2 *)
      ((2, 0), (0, 4));
      (* y=0, (2*2 + 3*0) mod 5 = 4 *)
      ((0, 1), (1, 3));
      (* y=1, (2*0 + 3*1) mod 5 = 3 *)
      ((1, 1), (1, 0));
      (* y=1, (2*1 + 3*1) mod 5 = 0 *)
    ]
  in

  List.iter
    (fun ((x, y), (exp_x, exp_y)) ->
      let res_x, res_y = Encryptor.Sha3.compute_pi_position x y in
      assert_equal
        ~msg:(Printf.sprintf "Pi position mismatch for (%d,%d)" x y)
        ~printer:(fun (x, y) -> Printf.sprintf "(%d,%d)" x y)
        (exp_x, exp_y) (res_x, res_y))
    test_cases

let test_rho_pi _ =
  let state = create_test_state () in
  let result = Encryptor.Sha3.rho_pi state in

  (* Test dimensions *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;
  assert_equal 5 (Array.length result.(0)) ~printer:string_of_int;

  (* Test that (0,0) is unchanged *)
  assert_equal ~printer:Int64.to_string state.(0).(0) result.(0).(0);

  (* Test first transformation (t=0) *)
  let new_x, new_y = Encryptor.Sha3.compute_pi_position 1 0 in
  let rotated = rotl64 state.(1).(0) (Encryptor.Sha3.compute_rho_offset 0) in
  assert_equal ~msg:"First rho-pi transformation failed"
    ~printer:Int64.to_string rotated
    result.(new_x).(new_y);

  (* Verify all positions are filled (no zeros except where expected) *)
  let zero_count = ref 0 in
  for x = 0 to 4 do
    for y = 0 to 4 do
      if Int64.equal result.(x).(y) 0L then incr zero_count
    done
  done;
  assert_bool "Too many zero values in result" (!zero_count < 25)

let test_chi_at_position _ =
  let state = create_test_state () in

  (* Test specific position (0,0) *)
  let result = Encryptor.Sha3.chi_at_position state 0 0 in
  let expected =
    Int64.logxor
      state.(0).(0)
      (Int64.logand (Int64.lognot state.(1).(0)) state.(2).(0))
  in
  assert_equal ~msg:"chi_at_position failed for (0,0)" ~printer:Int64.to_string
    expected result;

  (* Test position with wraparound (4,0) *)
  let result_wrap = Encryptor.Sha3.chi_at_position state 4 0 in
  let expected_wrap =
    Int64.logxor
      state.(4).(0)
      (Int64.logand (Int64.lognot state.(0).(0)) state.(1).(0))
  in
  assert_equal ~msg:"chi_at_position failed for wraparound case (4,0)"
    ~printer:Int64.to_string expected_wrap result_wrap

let test_chi _ =
  let state = create_test_state () in
  let result = Encryptor.Sha3.chi state in

  (* Test dimensions *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;
  assert_equal 5 (Array.length result.(0)) ~printer:string_of_int;

  (* Test that each position matches chi_at_position *)
  for x = 0 to 4 do
    for y = 0 to 4 do
      let expected = Encryptor.Sha3.chi_at_position state x y in
      assert_equal
        ~msg:(Printf.sprintf "chi transformation mismatch at (%d,%d)" x y)
        ~printer:Int64.to_string expected
        result.(x).(y)
    done
  done

let test_iota _ =
  let state = create_test_state () in
  let round = 0 in
  let result = Encryptor.Sha3.iota state round in

  (* Test dimensions *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;
  assert_equal 5 (Array.length result.(0)) ~printer:string_of_int;

  (* Test that only (0,0) is modified *)
  assert_equal ~msg:"(0,0) position not correctly transformed"
    ~printer:Int64.to_string
    (Int64.logxor state.(0).(0) keccak_round_constants.(round))
    result.(0).(0);

  (* Test that all other positions remain unchanged *)
  for x = 0 to 4 do
    for y = 0 to 4 do
      if not (x = 0 && y = 0) then
        assert_equal
          ~msg:(Printf.sprintf "Position (%d,%d) changed unexpectedly" x y)
          ~printer:Int64.to_string
          state.(x).(y)
          result.(x).(y)
    done
  done

let test_keccak_round _ =
  let state = create_test_state () in
  let round = 0 in
  let result = Encryptor.Sha3.keccak_round state round in

  (* Test dimensions *)
  assert_equal 5 (Array.length result) ~printer:string_of_int;
  assert_equal 5 (Array.length result.(0)) ~printer:string_of_int;

  (* Verify round transformation by applying each step manually *)
  let expected =
    state |> Encryptor.Sha3.theta |> Encryptor.Sha3.rho_pi |> Encryptor.Sha3.chi
    |> fun s -> Encryptor.Sha3.iota s round
  in

  (* Compare with expected result *)
  for x = 0 to 4 do
    for y = 0 to 4 do
      assert_equal
        ~msg:(Printf.sprintf "Round transformation mismatch at (%d,%d)" x y)
        ~printer:Int64.to_string
        expected.(x).(y)
        result.(x).(y)
    done
  done

let test_hex_of_string _ =
  let test_cases =
    [
      (* Empty string *)
      ("", "");
      (* Single byte *)
      (String.make 1 (char_of_int 0xab), "ab");
      (* Multiple bytes *)
      ( String.make 1 (char_of_int 0x12) ^ String.make 1 (char_of_int 0x34),
        "1234" );
    ]
  in

  List.iter
    (fun (input, expected) ->
      let result = Encryptor.Sha3.hex_of_string (Bytes.of_string input) in
      assert_equal
        ~msg:(Printf.sprintf "Hex conversion failed for input: %S" input)
        ~printer:(fun x -> x)
        expected result)
    test_cases

(********************************* SHA3 functionality tests
  *****************************)
(* Helper function to convert hex string to bytes *)
let hex_to_bytes hex =
  let hex = String.lowercase_ascii hex in
  let len = String.length hex in
  let bytes = Bytes.create (len / 2) in
  for i = 0 to (len / 2) - 1 do
    let high = int_of_char hex.[i * 2] in
    let low = int_of_char hex.[(i * 2) + 1] in
    let high = if high <= 57 then high - 48 else high - 87 in
    let low = if low <= 57 then low - 48 else low - 87 in
    Bytes.set bytes i (char_of_int ((high lsl 4) lor low))
  done;
  bytes

(* Helper function to convert bytes to hex string *)
let bytes_to_hex bytes =
  let len = Bytes.length bytes in
  let hex = Bytes.create (len * 2) in
  for i = 0 to len - 1 do
    let v = int_of_char (Bytes.get bytes i) in
    let high = if v lsr 4 <= 9 then (v lsr 4) + 48 else (v lsr 4) + 87 in
    let low =
      if v land 0xf <= 9 then (v land 0xf) + 48 else (v land 0xf) + 87
    in
    Bytes.set hex (i * 2) (char_of_int high);
    Bytes.set hex ((i * 2) + 1) (char_of_int low)
  done;
  Bytes.unsafe_to_string hex

let test_pad_input _ =
  (* Test string shorter than rate *)
  let padded2 = Encryptor.Sha3.pad_input "Hello" in
  let len2 = Bytes.length padded2 in

  (* Assert the length is valid *)
  assert_equal true (len2 > 5)
    ~msg:"Hello string padding should be longer than input"

let test_absorb _ =
  let state = Array.make_matrix 5 5 0L in
  let input = "test" in
  let padded = Encryptor.Sha3.pad_input input in
  Encryptor.Sha3.absorb state padded;

  (* Verify state is modified *)
  assert_bool "State should be modified"
    (Array.exists (fun row -> Array.exists (fun el -> el <> 0L) row) state)

(* Test cases for squeeze *)

(** [get_output_length hash_size] returns the output length in bytes for a given
    hash size in bits. *)
let get_output_length hash_size_bits = hash_size_bits / 8

let test_squeeze _ =
  let state = Array.make_matrix 5 5 0L in
  (* Set some known values in state *)
  state.(0).(0) <- 0x0123456789abcdefL;
  state.(1).(0) <- 0xfedcba9876543210L;

  (* Calculate the expected output length using the helper *)
  let expected_length = get_output_length 256 in

  let output = Encryptor.Sha3.squeeze state in
  assert_equal expected_length (Bytes.length output)
    ~msg:
      (Printf.sprintf "Expected output length: %d, but got: %d" expected_length
         (Bytes.length output))

(* Test cases for complete sha3_256 *)
let test_sha3_256 _ =
  (* Test vectors from NIST *)

  (* Test empty string *)
  let test_empty = Encryptor.Sha3.sha3_256 "" in
  let test_empty_hex = bytes_to_hex test_empty in
  Printf.printf "Empty string hash: %s\n" test_empty_hex;
  assert_equal
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    test_empty_hex ~msg:"Empty string hash does not match expected value";

  (* Test "abc" *)
  let test_abc = Encryptor.Sha3.sha3_256 "abc" in
  let test_abc_hex = bytes_to_hex test_abc in
  Printf.printf "abc string hash: %s\n" test_abc_hex;
  assert_equal
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    test_abc_hex ~msg:"'abc' hash does not match expected value";

  (* Test long input *)
  let test_long =
    Encryptor.Sha3.sha3_256
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  in
  let test_long_hex = bytes_to_hex test_long in
  Printf.printf "Long string hash: %s\n" test_long_hex;
  assert_equal
    "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
    test_long_hex ~msg:"Long string hash does not match expected value"

let test_expand_key _ =
  (* Test with a short key and maximum effective bits *)
  let key = "testkey" in
  let effective_bits = 1024 in
  let expanded_key = expand_key key effective_bits in

  (* Assert the length of the expanded key is 128 *)
  assert_equal 128 (Array.length expanded_key) ~printer:string_of_int;

  (* Check the first few values for consistency *)
  assert_bool "First byte of expanded key should not be zero"
    (expanded_key.(0) <> 0);

  assert_bool "Last byte of expanded key should not be zero"
    (expanded_key.(127) <> 0);

  (* Test with a shorter effective key size *)
  let effective_bits_short = 64 in
  let expanded_key_short = expand_key key effective_bits_short in

  (* Assert the length is still 128 but effective bits applied *)
  assert_equal 128 (Array.length expanded_key_short) ~printer:string_of_int;

  (* Print first few bytes for debugging *)
  Printf.printf "Expanded key (short effective bits): [";
  Array.iteri
    (fun i x -> if i < 10 then Printf.printf "0x%02x " x)
    expanded_key_short;
  Printf.printf "...]\n";

  (* Check if the effective bits are applied correctly *)
  let t3 = (effective_bits_short + 7) / 8 in
  let last_used_index = t3 - 1 in
  let unused_bytes = Array.sub expanded_key_short t3 (128 - t3) in
  Array.iter (fun x -> assert_equal 83 x ~printer:string_of_int) unused_bytes;

  (* Ensure values after the effective key size are zeroed *)
  assert_equal 0 expanded_key_short.(last_used_index + 1) ~printer:string_of_int

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
         (*SHA3*)
         "rotl64 basic rotation" >:: rotl64_test1;
         "rotl64 wraparound" >:: rotl64_test2;
         "rotl64 no rotation" >:: rotl64_test3;
         "to_state empty initialization" >:: to_state_test1;
         "to_state consistent initialization" >:: to_state_test2;
         "from_state with values" >:: from_state_test1;
         "from_state all zeros" >:: from_state_test2;
         "test_xor_slice_simple" >:: test_xor_slice_simple;
         "test_compute_column_parity" >:: test_compute_column_parity;
         "test_compute_theta_d" >:: test_compute_theta_d;
         "test_theta" >:: test_theta;
         "test_compute_rho_offset" >:: test_compute_rho_offset;
         "test_compute_pi_position" >:: test_compute_pi_position;
         "test_rho_pi" >:: test_rho_pi;
         "test_chi_at_position" >:: test_chi_at_position;
         "test_chi" >:: test_chi;
         "test_iota" >:: test_iota;
         "test_keccak_round" >:: test_keccak_round;
         "test_hex_of_string" >:: test_hex_of_string;
         "test_pad_input" >:: test_pad_input;
         "test_absorb" >:: test_absorb;
         "test_squeeze" >:: test_squeeze;
         (* "test_sha3_256" >:: test_sha3_256; *)
         "test_expand_key" >:: test_expand_key;
       ]

let _ = run_test_tt_main tests
