(* lib/rsa.ml *)

open Util

module Rsa = struct
  (* Modular exponentiation function *)
  let rec mod_exp base exp modulus =
    if exp = 0 then 1
    else if exp mod 2 = 0 then
      let half = mod_exp base (exp / 2) modulus in
      half * half mod modulus
    else base * mod_exp base (exp - 1) modulus mod modulus

  (* RSA encryption function *)
  let rsa_encrypt message (e, n) = mod_exp message e n

  (* RSA decryption function *)
  let rsa_decrypt ciphertext (d, n) = mod_exp ciphertext d n

  (* RSA key generation *)
  let generate_keys () =
    let p = generate_prime 1000 10000 in
    let q = generate_prime 1000 10000 in
    let n = p * q in

    (* Calculate eulers totient function φ(n) *)
    let phi_n = (p - 1) * (q - 1) in

    (* Choose a public exponent 'e' such that gcd(e, φ(n)) = 1 *)
    let rec choose_e phi_n =
      let e = Random.int (phi_n - 2) + 2 in
      if find_gcd e phi_n = 1 then e else choose_e phi_n
    in
    let e = choose_e phi_n in

    (* Use Util.mod_inv to calculate private exponent 'd' such that e * d ≡ 1
       (mod φ(n)) *)
    let d = mod_inv e phi_n in

    (* Public key: (e, n), Private key: (d, n) *)
    ((e, n), (d, n))
end
