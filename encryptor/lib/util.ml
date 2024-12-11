(* lib/util.ml *)

(* Check if a number [n] is prime *)
let is_prime n =
  let rec check_divisors d =
    if d * d > n then true
    else if n mod d = 0 then false
    else check_divisors (d + 1)
  in
  if n < 2 then false else check_divisors 2

(* Generate a random prime number in the range [min, max] *)
let rec generate_prime min max =
  let prime = Random.int (max - min + 1) + min in
  if is_prime prime then prime else generate_prime min max

(* Find the GCD of two numbers *)
let rec find_gcd a b =
  match b with
  | 0 -> a
  | b -> find_gcd b (a mod b)

(*Finds modular inverse of a number. Reference:
  "https://rosettacode.org/wiki/Modular_inverse#Translation_of:_Haskell"*)
let rec gcd_ext a = function
  | 0 -> (1, 0, a)
  | b ->
      let s, t, g = gcd_ext b (a mod b) in
      (t, s - (a / b * t), g)

(*Finds modular inverse using gcd_ext helper.*)
let mod_inv a m =
  let mk_pos x = if x < 0 then x + m else x in
  match gcd_ext a m with
  | i, _, 1 -> mk_pos i
  | _ -> failwith "mod_inv"

(* Function to read a file and return its contents *)
let read_file filename =
  try
    let in_channel = open_in filename in
    let file_content =
      really_input_string in_channel (in_channel_length in_channel)
    in
    close_in in_channel;
    Some file_content
  with Sys_error err ->
    Printf.printf "Error: %s\n" err;
    None
