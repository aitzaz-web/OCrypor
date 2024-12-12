(* ECC Implementation *)

module ECC = struct
  (* Finite Field Arithmetic *)
  
  type point = Infinity | Point of int * int
  type keypair = { private_key : int; public_key : point }
  let mod_add a b p = (a + b) mod p
  let mod_sub a b p = (a - b + p) mod p
  let mod_mul a b p = (a * b) mod p
  

  let rec egcd a b =
    if b = 0 then (a, 1, 0)
    else
      let (g, x, y) = egcd b (a mod b) in
      (g, y, x - (a / b) * y)

  let mod_inv a p =
    let (g, x, _) = egcd a p in
    if g <> 1 then failwith "No modular inverse"
    else (x mod p + p) mod p

  let is_infinity = function Infinity -> true | _ -> false

  let is_on_curve (x, y) a b p =
    let lhs = mod_mul y y p in
    let rhs =
      mod_add (mod_mul (mod_mul x x p) x p)
        (mod_add (mod_mul a x p) b p) p
    in
    lhs = rhs

  let add p1 p2 a p =
    match (p1, p2) with
    | Infinity, q | q, Infinity -> q
    | Point (x1, y1), Point (x2, y2) ->
        if x1 = x2 && (y1 <> y2 || y1 = 0) then Infinity
        else
          let m =
            if x1 = x2 then
              mod_mul (mod_add (3 * x1 * x1) a p) (mod_inv (2 * y1) p) p
            else
              mod_mul (mod_sub y2 y1 p) (mod_inv (mod_sub x2 x1 p) p) p
          in
          let x3 = mod_sub (mod_sub (m * m) x1 p) x2 p in
          let y3 = mod_sub (mod_mul m (mod_sub x1 x3 p) p) y1 p in
          Point (x3, y3)

  let rec scalar_mult k point a p =
    if k = 0 then Infinity
    else if k mod 2 = 0 then
      scalar_mult (k / 2) (add point point a p) a p
    else add point (scalar_mult (k - 1) point a p) a p

  let generate_keys base_point a b p n =
    let private_key = Random.int (n - 1) + 1 in
    let public_key = scalar_mult private_key base_point a p in
    { private_key; public_key }

  let encrypt msg base_point public_key a b p n =
    let k = Random.int (n - 1) + 1 in
    let c1 = scalar_mult k base_point a p in
    let c2 = add (Point (msg, 0)) (scalar_mult k public_key a p) a p in
    (c1, c2)

  let decrypt (c1, c2) private_key a p =
    match add c2 (scalar_mult private_key c1 a p) a p with
    | Point (x, _) -> x
    | Infinity -> failwith "Decryption failed"
  
  let point_to_string point =
    match point with
    | Infinity -> "Infinity"
    | Point (x, y) -> Printf.sprintf "(%d, %d)" x y

  
end
